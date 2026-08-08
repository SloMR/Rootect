#!/usr/bin/env python3
"""Verifies a Rootect attestation chain, the way a backend should.

The device only reports. This decides, somewhere an attacker holding the phone cannot reach.

  python scripts/verify-attestation.py <chain.der...> --challenge <hex> [--offline]

Needs `cryptography` (pip install cryptography).
"""

import hashlib
import sys
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
except ImportError:
    sys.exit("needs: pip install cryptography")

ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"
STATUS_URL = "https://android.googleapis.com/attestation/status"

# Google's published roots, by SHA-256 of their SubjectPublicKeyInfo:
#   https://developer.android.com/privacy-and-security/security-key-attestation
KNOWN_ROOT_KEYS = {
    "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae":
        "RSA-4096 root, serial f92009e853b6b045",
    "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec":
        "Key Attestation CA1 (P-384), in effect since 2026-02-01",
}

BOOT_STATE = {0: "Verified", 1: "SelfSigned", 2: "Unverified", 3: "Failed"}
SECURITY_LEVEL = {0: "Software", 1: "TrustedEnvironment", 2: "StrongBox"}

# Positions inside the KeyDescription sequence, and inside RootOfTrust within it.
KEY_SECURITY_LEVEL = 1
KEY_CHALLENGE = 4
KEY_TEE_ENFORCED = 7
TAG_ROOT_OF_TRUST = 704
ROT_DEVICE_LOCKED = 1
ROT_BOOT_STATE = 2


# ── DER ───────────────────────────────────────────────────────────────────────

def der_elements(data, start=0, end=None):
    """Yields (tag, content_start, content_end) for each element in a DER body."""
    end = len(data) if end is None else end
    pos = start

    while pos < end:
        tag = data[pos]
        pos += 1

        if tag & 0x1F == 0x1F:  # multi-byte tag number
            tag = 0
            while True:
                byte = data[pos]
                pos += 1
                tag = (tag << 7) | (byte & 0x7F)
                if not byte & 0x80:
                    break
        else:
            tag &= 0x1F

        length = data[pos]
        pos += 1
        if length & 0x80:  # long form: the low bits count the length's own bytes
            count = length & 0x7F
            length = int.from_bytes(data[pos:pos + count], "big")
            pos += count

        yield tag, pos, pos + length
        pos += length


def parse_attestation(cert):
    """Returns (security_level, challenge, root_of_trust) from the attestation extension."""
    ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(ATTESTATION_OID))
    raw = ext.value.value

    _, body_start, body_end = next(der_elements(raw))
    fields = list(der_elements(raw, body_start, body_end))

    level = int.from_bytes(raw[slice(*fields[KEY_SECURITY_LEVEL][1:])], "big")
    challenge = raw[slice(*fields[KEY_CHALLENGE][1:])]

    return level, challenge, find_root_of_trust(raw, fields[KEY_TEE_ENFORCED])


def find_root_of_trust(raw, tee_enforced):
    """What the hardware says about the bootloader, or None if it did not say."""
    for tag, start, end in der_elements(raw, tee_enforced[1], tee_enforced[2]):
        if tag != TAG_ROOT_OF_TRUST:
            continue
        _, inner_start, inner_end = next(der_elements(raw, start, end))
        rot = list(der_elements(raw, inner_start, inner_end))
        return {
            "deviceLocked": raw[rot[ROT_DEVICE_LOCKED][1]] != 0,
            "verifiedBootState": int.from_bytes(raw[slice(*rot[ROT_BOOT_STATE][1:])], "big"),
        }
    return None


# ── Checks ────────────────────────────────────────────────────────────────────

def check_signatures(chain):
    """Every certificate must be signed by the one above it."""
    ok = True
    for child, parent in zip(chain, chain[1:]):
        try:
            verify_signed_by(child, parent)
            print(f"  ok   {child.subject.rfc4514_string()[:50]:<50} signed by parent")
        except Exception as e:
            print(f"  FAIL signature: {e}")
            ok = False
    return ok


def verify_signed_by(child, parent):
    """Raises unless the parent's key really signed the child."""
    key = parent.public_key()
    if isinstance(key, ec.EllipticCurvePublicKey):
        key.verify(child.signature, child.tbs_certificate_bytes,
                   ec.ECDSA(child.signature_hash_algorithm))
    elif isinstance(key, rsa.RSAPublicKey):
        key.verify(child.signature, child.tbs_certificate_bytes,
                   padding.PKCS1v15(), child.signature_hash_algorithm)
    else:
        # Refuse rather than skip: an unchecked link is an unsigned one.
        raise ValueError(f"unsupported key type {type(key).__name__}")


def check_root(chain):
    """The chain has to lead to a root Google published, or it proves nothing."""
    root = chain[-1]
    fingerprint = hashlib.sha256(
        root.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()

    print(f"\n  root subject : {root.subject.rfc4514_string()}")
    print(f"  root key     : sha256:{fingerprint}")
    print(f"  self-signed  : {root.subject == root.issuer}")

    known = KNOWN_ROOT_KEYS.get(fingerprint)
    if known:
        print(f"  root pinned  : yes ({known})")
        return True

    print("  root pinned  : NO - unrecognised root, treat as untrusted")
    return False


def revoked_serials(offline):
    """Google's revocation list, keyed by serial in lowercase hex. None if unavailable."""
    if offline:
        return None
    try:
        import json
        import urllib.request
        with urllib.request.urlopen(STATUS_URL, timeout=15) as response:
            return json.load(response).get("entries", {})
    except Exception as e:
        print(f"  WARN could not fetch revocation list: {type(e).__name__}")
        return None


def check_revocation(chain, entries):
    """Leaked keyboxes are what TrickyStore needs, and revocation is how they get caught."""
    if entries is None:
        print("  revocation      : NOT CHECKED - treat the result as provisional")
        return True

    ok = True
    for cert in chain:
        serial = format(cert.serial_number, "x")
        revoked = entries.get(serial) or entries.get(serial.zfill(32))
        if revoked:
            print(f"  REVOKED {serial}: {revoked.get('reason')}")
            ok = False

    if ok:
        print(f"  revocation      : clean ({len(entries)} revoked keys checked)")
    return ok


def check_attestation(leaf, expected_challenge):
    """What the leaf actually attests: hardware backing, our challenge, boot state."""
    try:
        level, challenge, rot = parse_attestation(leaf)
    except Exception as e:
        print(f"\n  REJECT no usable attestation extension: {type(e).__name__}")
        return False

    print(f"\n  security level    : {level} ({SECURITY_LEVEL.get(level, '?')})")
    print(f"  challenge         : {challenge.hex()}")
    if rot:
        state = BOOT_STATE.get(rot["verifiedBootState"], "?")
        print(f"  deviceLocked      : {rot['deviceLocked']}")
        print(f"  verifiedBootState : {rot['verifiedBootState']} ({state})")

    ok = True

    if expected_challenge is not None:
        matches = challenge.hex().lower() == expected_challenge.lower()
        print(f"\n  challenge matches : {matches}")
        if not matches:
            print("  FAIL replayed or wrong chain")
            ok = False

    if level == 0:
        print("\n  REJECT software-only attestation proves nothing")
        ok = False

    if rot and (not rot["deviceLocked"] or rot["verifiedBootState"] != 0):
        print("\n  REJECT hardware reports an unlocked or unverified device")
        ok = False

    return ok


# ── Entry point ───────────────────────────────────────────────────────────────

def parse_args(argv):
    """Returns (paths, challenge_hex, offline)."""
    offline = "--offline" in argv
    argv = [a for a in argv if a != "--offline"]

    challenge = None
    if "--challenge" in argv:
        i = argv.index("--challenge")
        challenge = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]

    return argv, challenge, offline


def main():
    paths, challenge, offline = parse_args(sys.argv[1:])
    if not paths:
        sys.exit(__doc__)

    chain = [x509.load_der_x509_certificate(Path(p).read_bytes()) for p in paths]
    print(f"chain of {len(chain)} certificates\n")

    # Every check runs even after one fails, so a bad chain reports all its problems at once.
    ok = check_signatures(chain)
    ok = check_root(chain) and ok
    print()
    ok = check_revocation(chain, revoked_serials(offline)) and ok
    ok = check_attestation(chain[0], challenge) and ok

    print(f"\nverdict: {'TRUSTED' if ok else 'NOT TRUSTED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
