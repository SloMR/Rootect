#!/usr/bin/env python3
"""A stand-in for the backend a host app would run.

Exists so the sample can demonstrate the pattern that works — decide on the server — rather
than the local `if` that does not.

  GET  /challenge  -> a single-use nonce
  POST /verify     -> {challenge, chain[], clientReport} -> verdict

  python scripts/mock-verifier.py
  adb reverse tcp:8080 tcp:8080     # so the phone can reach this machine

Needs `cryptography` (pip install cryptography).
"""

import base64
import hashlib
import importlib.util
import json
import secrets
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

# The verifier is the reusable piece; this file is only transport around it. Loaded by path
# because the filename has a hyphen and cannot be imported normally.
_spec = importlib.util.spec_from_file_location(
    "verifier", Path(__file__).parent / "verify-attestation.py"
)
verifier = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verifier)

PORT = 8080

# Challenges issued and not yet used. Single use is the entire point: it is what stops a
# chain captured once from being replayed forever.
_outstanding = set()


# ── Verification ──────────────────────────────────────────────────────────────

def chain_is_authentic(chain):
    """Signatures and root pin. Returns a reason, or None when the chain is genuine."""
    for child, parent in zip(chain, chain[1:]):
        try:
            verifier.verify_signed_by(child, parent)
        except Exception as e:
            return f"broken chain signature: {type(e).__name__}"

    root_key = hashlib.sha256(
        chain[-1].public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()
    if root_key not in verifier.KNOWN_ROOT_KEYS:
        return "chain does not lead to a Google attestation root"

    return None


def revoked_reason(chain):
    """Whether any certificate has been revoked, which is what answers a leaked keybox."""
    entries = verifier.revoked_serials(offline=False)
    if not entries:
        return None

    for cert in chain:
        serial = format(cert.serial_number, "x")
        revoked = entries.get(serial) or entries.get(serial.zfill(32))
        if revoked:
            return f"revoked certificate {serial}: {revoked.get('reason')}"
    return None


def hardware_complaints(level, challenge, rot, challenge_hex):
    """Everything the hardware and the challenge disagree with."""
    reasons = []

    if challenge.hex().lower() != challenge_hex.lower():
        reasons.append("challenge mismatch - replayed or belongs to another session")
    if challenge_hex not in _outstanding:
        reasons.append("challenge was not issued by us, or was already used")
    if level == 0:
        reasons.append("software-only attestation proves nothing")

    if rot:
        if not rot["deviceLocked"]:
            reasons.append("hardware reports the bootloader unlocked")
        if rot["verifiedBootState"] != 0:
            state = verifier.BOOT_STATE.get(rot["verifiedBootState"], "?")
            reasons.append(f"hardware reports verified boot state {state}")

    return reasons


def contradiction(rot, client_report):
    """The reason to send the report and the chain together.

    A hooked client answers "clean" while the hardware it cannot reach says otherwise.
    Hiding this would mean suppressing the attestation, which is not forgeable.
    """
    if not rot or client_report is None:
        return None

    hardware_says_modified = not rot["deviceLocked"] or rot["verifiedBootState"] != 0
    if client_report.get("isRooted") is False and hardware_says_modified:
        return ("CONTRADICTION: client reported a clean device while its own secure "
                "hardware reports the bootloader unlocked - the client is lying")
    return None


def verify(chain, challenge_hex, client_report):
    """Returns (trusted, reasons). Fatal checks first, so a forged chain stops early."""
    fatal = chain_is_authentic(chain) or revoked_reason(chain)
    if fatal:
        return False, [fatal]

    try:
        level, challenge, rot = verifier.parse_attestation(chain[0])
    except Exception as e:
        return False, [f"no usable attestation extension: {type(e).__name__}"]

    reasons = hardware_complaints(level, challenge, rot, challenge_hex)
    reasons += [r for r in [contradiction(rot, client_report)] if r]

    return not reasons, reasons


# ── HTTP ──────────────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path != "/challenge":
            return self.reply(404, {"error": "not found"})

        challenge = secrets.token_hex(32)
        _outstanding.add(challenge)
        print(f"  issued challenge {challenge[:16]}...")
        self.reply(200, {"challenge": challenge})

    def do_POST(self):
        if self.path != "/verify":
            return self.reply(404, {"error": "not found"})

        try:
            request = self.read_json()
            chain = [x509.load_der_x509_certificate(base64.b64decode(c))
                     for c in request["chain"]]
        except Exception as e:
            return self.reply(400, {"error": f"malformed request: {type(e).__name__}"})

        challenge = request.get("challenge", "")
        trusted, reasons = verify(chain, challenge, request.get("clientReport"))
        _outstanding.discard(challenge)  # single use, whether it passed or not

        print(f"  verdict: {'TRUSTED' if trusted else 'NOT TRUSTED'}")
        for reason in reasons:
            print(f"    - {reason}")

        self.reply(200, {
            "trusted": trusted,
            "reasons": reasons,
            "certificates": len(chain),
        })

    def read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length))

    def reply(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # the verdict lines are the interesting output


def main():
    # So verdicts appear as they happen even when the output is piped to a file.
    sys.stdout.reconfigure(line_buffering=True)

    print(f"mock verifier on http://127.0.0.1:{PORT}")
    print("run `adb reverse tcp:8080 tcp:8080` so the device can reach it\n")
    try:
        HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
