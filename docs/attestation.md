# Hardware attestation

Everything else Rootect reports is computed on the device. This is not, and that is the
entire point.

## Why it is different

The device's secure element (TEE, or StrongBox on some hardware) holds a private key that
software cannot read — not the OS, not root, not an instrumentation framework. Ask it to
generate a key and it hands back a certificate chain stating what kind of device it is
running on, signed by that key.

An attacker with full control of the phone can refuse to produce a chain, send an old one, or
invent one. They cannot produce a *valid* chain that says something false, because they
cannot sign with a key they cannot reach.

```
┌──────────────── a device the attacker may own ─────────────────┐
│                                                                 │
│   Rootect signals ............ can be altered                   │
│   local "am I rooted" answer .. can be altered                  │
│   attestation chain .......... cannot be forged                 │
│                                 (the key lives in hardware)     │
│                                                                 │
└───────────────────────────────┬─────────────────────────────────┘
                                │  network
┌───────────────────────────────┴─────────────────────────────────┐
│  your server — where the verdict is decided                     │
└─────────────────────────────────────────────────────────────────┘
```

The rule that follows: **verifying the chain on the device is pointless.** It reduces to a
local boolean, with every weakness of a local boolean. The chain has to leave the device.

## The round trip

```
   Your app                    Your server                  Google
      │                             │                          │
      │  1. "give me a challenge"   │                          │
      │────────────────────────────>│                          │
      │                             │  random 32 bytes,        │
      │  2. challenge               │  stored, single use      │
      │<────────────────────────────│                          │
      │                             │                          │
 ┌────┴──────────┐                  │                          │
 │ 3. secure     │  RootectAttestation.chain(challenge)        │
 │    hardware   │  signs a chain embedding the challenge      │
 │    signs      │  and the boot state                         │
 └────┬──────────┘                  │                          │
      │                             │                          │
      │  4. chain + local report    │                          │
      │────────────────────────────>│                          │
      │                             │  5. revocation list      │
      │                             │─────────────────────────>│
      │                             │<─────────────────────────│
      │                             │                          │
      │  6. verdict                 │  verify: signatures,     │
      │<────────────────────────────│  root, revocation,       │
      │                             │  challenge, boot state   │
```

Step 1 matters more than it looks. **The challenge must come from your server and be used
once.** A challenge the device picks proves nothing — the attacker replays a chain captured
on a clean phone and it verifies perfectly.

## What the chain looks like

Leaf first, root last. Real output from a Galaxy A15:

```
 attest-0.der   leaf — "Android Keystore Key"
   │              └── extension 1.3.6.1.4.1.11129.2.1.17
   │                    ├── attestationChallenge ← the nonce you issued
   │                    ├── securityLevel        ← TrustedEnvironment | StrongBox
   │                    └── rootOfTrust
   │                          ├── deviceLocked        ← bootloader locked?
   │                          └── verifiedBootState   ← Verified | Unverified | …
   │ signed by
 attest-1.der   device key, "O=TEE"
   │ signed by
 attest-2.der   "Droid CA3, Google LLC"
   │ signed by
 attest-3.der   "Droid CA2, Google LLC"
   │ signed by
 attest-4.der   ROOT — "Key Attestation CA1"   ← pin this
```

Chain length varies by vendor and provisioning method. A Pixel 5 produced 4 certificates; the
Galaxy A15 produced 5. **Never assume a length** — walk to the end.

The facts you actually want live in the leaf's extension. Everything above it exists to prove
the leaf is genuine.

## Using it

### On the device

```kotlin
// Single-use, issued by your server. Never generate this locally.
val challenge: ByteArray = api.requestChallenge()

// DER-encoded certificates, leaf first. Null means this device would not attest.
val chain: List<ByteArray>? = RootectAttestation.chain(challenge)

if (chain == null) {
    // Not proof of anything bad - some devices genuinely cannot attest.
    // Report it and let the server decide what that is worth.
    api.submit(chain = null, report = Rootect.analyze(context))
} else {
    api.submit(chain, Rootect.analyze(context))
}
```

Send the local report **alongside** the chain. The reason is below, and it is free.

`Rootect.analyze()` can also fold attestation into the normal report:

```kotlin
Rootect.analyze(context, RootectConfig(hardwareAttestation = true))
```

That emits `ATTESTATION_BOOT_UNVERIFIED`, `ATTESTATION_SOFTWARE_ONLY` and
`ATTESTATION_CONTRADICTS_PROPERTIES` as ordinary signals. Useful for telemetry — but it is a
*local* result, so it carries local trust. It is not a substitute for the round trip.

It is also slow: it generates a key. Call it on considered checks, not on every screen.

### On your server

Reject on the first failure:

| # | Check | Why |
|---|---|---|
| 1 | Each certificate signed by the next | A chain that does not chain is a list of files |
| 2 | Root is one Google publishes | The only thing an attacker cannot fake |
| 3 | No certificate revoked | Catches leaked hardware keys |
| 4 | Challenge is yours, and unused | Stops replay |
| 5 | Security level is hardware-backed | Software attestation proves nothing |
| 6 | `deviceLocked` and boot `Verified` | The actual answer |

**There are currently two roots in force.** The older RSA-4096 root, and *Key Attestation
CA1* (P-384), effective 2026-02-01. Pin both. Recently provisioned devices use the newer one:
the Galaxy A15 above chains to it, and pinning only the older root would have rejected a
stock, locked, unmodified phone.

Fetch the authoritative lists from:

```
https://android.googleapis.com/attestation/root     # accepted roots
https://android.googleapis.com/attestation/status   # revoked keys
```

`scripts/verify-attestation.py` implements all six checks and is the reference.

### The cross-check worth having

A client can be made to lie about the report. It cannot be made to lie about the chain. So
compare them:

```python
hardware_says_modified = not root_of_trust.device_locked
if client_report["isRooted"] is False and hardware_says_modified:
    reject("client claims clean; its own hardware says unlocked")
```

Suppressing Rootect's local signals now produces a **contradiction** — a client insisting it
is clean while carrying hardware-signed evidence that it is not. Removing the evidence too
means sending no attestation, which is equally a decision you get to make.

The lie becomes the detection, and it is judged where the attacker has no reach.

## What it looks like in practice

Same code, two devices, opposite answers:

| | Pixel 5, rooted | Galaxy A15, stock |
|---|---|---|
| Root pinned | RSA-4096 | Key Attestation CA1 |
| Security level | TrustedEnvironment | TrustedEnvironment |
| `deviceLocked` | `False` | `True` |
| `verifiedBootState` | `Unverified` | `Verified` |
| Verdict | `NOT TRUSTED` | `TRUSTED` |

The rooted phone reports itself honestly at the hardware level **even while running an
instrumentation framework**, because that part is not up to the software.

## Trying it locally

```bash
python scripts/mock-verifier.py       # terminal 1
adb reverse tcp:8080 tcp:8080         # let the device reach your machine
./gradlew :sample:installDebug
```

Open the sample, press **Verify off-device**. That exercises the whole round trip against a
server implementing all six checks.

To verify a saved chain instead:

```bash
python scripts/verify-attestation.py chain/attest-0.der chain/attest-1.der … --challenge <hex>
```

## Limits

- **Forged attestation exists.** Tools using leaked hardware keys can produce chains that
  verify. Revocation checking catches the keys Google knows about, which is most of them; one
  nobody has reported yet still passes.
- **Not every device can attest.** Older and some low-end hardware returns nothing, or
  software-only attestation. Treat that as *"could not verify"*, never *"clean"*.
- **The root list changes.** Google added one in February 2026. A hardcoded pin will go stale
  — refresh it from the published endpoint rather than trusting this document forever.
- **Attestation says nothing about instrumentation.** It reports bootloader and boot state. A
  locked, verified device can still be running a debugger. Use it together with the local
  signals, not instead of them.
