# Hardware attestation

Everything else Rootect reports is computed on the device. This is not, and that is the
entire point.

## Why it is different

The device's secure element (TEE, or StrongBox on some hardware) holds a private key that
software cannot read — not the OS, not root, not an instrumentation framework. Ask it to
generate a key and it hands back a certificate chain stating what kind of device it is
running on, signed by that key.

An attacker can withhold, replay, relay, or invent a chain. A backend accepts one only after
validating its path, freshness, app identity, boot state, and Google's revocation list.

```
┌──────────────── a device the attacker may own ─────────────────┐
│                                                                 │
│   Rootect signals ............ can be altered                   │
│   local "am I rooted" answer .. can be altered                  │
│   attestation chain .......... hardware-signed evidence         │
│                                 requiring server validation    │
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
      │  4. challenge, chain, report│                          │
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
Galaxy A15 produced 5. Accept a bounded list rather than one fixed length, then walk to the end.

Rootect puts the statement in the target leaf. The verifier requires exactly that shape and
rejects an attestation extension on any issuer, preventing a signed-child extension attack.

### Samsung and other vendors

Rootect uses the standard [Android Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation)
API. A Samsung or other OEM device whose chain ends at a pinned Google root follows the same
verification path. A device using another root fails closed until your backend explicitly
adds and audits that trust anchor.

[Samsung Knox Enhanced Attestation](https://docs.samsungknox.com/dev/knox-attestation/enhanced-attestation-v3/)
is separate. It uses Samsung Attestation Keys, the Knox Warranty Bit, Samsung roots and a
Samsung attestation service. Rootect does not implement that proprietary flow.

The tested Galaxy A15 showed why this matters: standard Android attestation accepted its
locked, Verified current boot while `ro.boot.warranty_bit=1` reported historical Knox
tampering. Rootect emits `KNOX_WARRANTY_BIT_TRIPPED` locally, but only Knox Enhanced
Attestation can make that historical verdict authoritative off-device.

## Using it

### On the device

```kotlin
// Single-use, issued by your server. Never generate this locally.
val challenge: ByteArray = api.requestChallenge()

// DER-encoded certificates, leaf first. Null means this device would not attest.
val chain: List<ByteArray>? = RootectAttestation.chain(challenge)

// The chain is the authoritative evidence. The local report rides along as untrusted runtime
// signals the chain cannot see; your server gates on the chain and only weighs the report.
api.submitAttestation(challenge, chain, Rootect.analyze(context))
```

`null` is not proof of compromise; some devices genuinely cannot attest — treat it as unknown,
never clean. The local report is untrusted: use it to tighten policy, never as trusted evidence.

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
| 1 | Chain shape, names and signatures | Blocks forged and extended paths |
| 2 | Root is one Google publishes | Establishes the trust anchor |
| 3 | Certificate validity policy | Enforces RKP expiry |
| 4 | Revocation list is available and clean | Catches known leaked keys |
| 5 | Challenge is yours, fresh and single-use | Stops replay |
| 6 | Attestation and KeyMint levels match and are hardware-backed | Rejects software or inconsistent claims |
| 7 | Key origin is hardware-generated | Rejects imported keys |
| 8 | Hardware `rootOfTrust` is present | Missing evidence fails closed |
| 9 | Boot is locked and `Verified` | Enforces device posture |
| 10 | Package, version and signer match | Binds evidence to your app |

**There are currently two roots in force.** The older RSA-4096 root, and *Key Attestation
CA1* (P-384), effective 2026-02-01. Pin both. Recently provisioned devices use the newer one:
the Galaxy A15 above chains to it, and pinning only the older root would have rejected a
currently locked, Verified phone.

The authoritative lists are:

```
https://android.googleapis.com/attestation/root     # accepted roots
https://android.googleapis.com/attestation/status   # revoked keys
```

Use Google's maintained Kotlin verifier instead of maintaining another certificate parser.
Build [android/keyattestation](https://github.com/android/keyattestation) from its current
upstream source, vendor it or publish it to your internal Maven repository, and rerun the
attestation tests whenever upstream changes.

The complete example is one Ktor source file:
`attestation-server/src/main/kotlin/io/github/rootect/attestation/AttestationServer.kt`.
It starts `/challenge` and `/verify`, bounds input, consumes each challenge once, and applies the
Google, application-identity and verified-boot policies. Its small memory challenge store is only
for running the sample. Replace it with an atomic, short-lived Redis or database record bound to
the authenticated account and transaction. Put the routes behind TLS, authentication and rate
limiting in production.

The example module uses Google's source as an included build because the maintained verifier is
not published as a Maven artifact. Pass its directory when building:

```bash
./gradlew :attestation-server:test -PkeyAttestationPath=/path/to/keyattestation
./gradlew :attestation-server:run -PkeyAttestationPath=/path/to/keyattestation
```

Set `ROOTECT_APP_ID`, `ROOTECT_SIGNING_SHA256` and `ROOTECT_MIN_VERSION` before starting it. The
default revocation source caches Google's list for one hour, bounds network waits, and returns
HTTP 503 when verification infrastructure is unavailable.

### Layered evidence: a hardware gate plus an untrusted runtime report

The two inputs cover different threats, so the sample sends both and the server keeps them
distinct:

- **The hardware chain is the authoritative gate.** It proves boot integrity — bootloader
  locked, verified boot, app identity, key origin, revocation — and `attestationTrusted`
  comes only from it.
- **The local Rootect report is untrusted, complementary evidence.** The chain is blind to
  *runtime* compromise — Frida/Xposed hooking, an attached debugger, a device's historical
  Knox tamper — so the client sends its `signals` alongside the chain. A hooked client can
  forge them, so they never grant access; the server echoes them as `clientSignals` for your
  policy to weigh (block, degrade, log), and they catch honest or commodity compromise the
  chain cannot see.

Because the report is signed by nothing it cannot be trusted on its own — but it can convict a
liar. If a client claims clean (`isRooted=false`) while its own chain validated as
unlocked/unverified, the server returns `contradiction=true`: the client tampered with its own
detection. Suppressing the local signals then produces that contradiction; sending no
attestation at all is itself an unknown you must handle, never a clean result.

### Fail closed when the server is unavailable

Treat every state except an accepted server response as unable to access the protected operation:
not started, pending, timeout, malformed response, unavailable revocation data, missing
attestation, and rejected attestation. Clear any earlier approval before retrying so a stale green
result cannot survive a server outage.

The sample does this automatically. Its local Rootect dashboard remains available for
diagnostics, but the separate **Hardware attestation** card starts paused and contacts the backend
on launch. Only `attestationTrusted=true` changes that card to green and grants access. A verified
rejection is red and forces the overall security banner to `CRITICAL`, even if a hook forged an empty
local report. An unreachable server is yellow and says `Server unavailable`: access still fails
closed, the top status becomes `UNVERIFIED`, and the UI does not falsely accuse the device when no
verdict was returned.

That card is still UI inside an attacker-controlled process: Frida can repaint it or replace
its boolean. In a real app, the backend must enforce the decision by withholding the protected
data, token, or operation. Never send a protected secret first and ask the app to hide it after
a local check.

## What it looks like in practice

Same code, two devices, opposite answers:

| | Pixel 5, rooted | Galaxy A15, current boot |
|---|---|---|
| Root pinned | RSA-4096 | Key Attestation CA1 |
| Security level | TrustedEnvironment | TrustedEnvironment |
| `deviceLocked` | `False` | `True` |
| `verifiedBootState` | `Unverified` | `Verified` |
| Android verdict | `NOT TRUSTED` | `TRUSTED` |
| Knox warranty bit | — | `1` — outside this chain |

The rooted phone reports itself honestly at the hardware level **even while running an
instrumentation framework**, because that part is not up to the software.

## Connecting the sample

```bash
apksigner verify --print-certs sample/build/outputs/apk/debug/sample-debug.apk
adb reverse tcp:8080 tcp:8080
./gradlew :sample:installDebug
```

Start the Ktor example and open the sample. It verifies automatically; **Verify again** repeats the
round trip. `POST /challenge` returns a stored challenge as hex;
`POST /verify` accepts that hex
plus the leaf-first DER chain encoded as Base64 and returns `attestationTrusted`, `reasons`, and
`certificates`.

## Limits

- **Forged attestation exists.** Tools using leaked hardware keys can produce chains that
  verify. Revocation checking catches the keys Google knows about, which is most of them; one
  nobody has reported yet still passes.
- **A nonce stops replay, not live relay.** Bind challenges to the account and transaction,
  rate-limit them, and treat clean-device proxying as backend fraud detection.
- **Not every device can attest.** Older and some low-end hardware returns nothing, or
  software-only attestation. Treat that as *"could not verify"*, never *"clean"*.
- **The root list changes.** Google added one in February 2026. A hardcoded pin will go stale
  — refresh it from the published endpoint rather than trusting this document forever.
- **Attestation says nothing about instrumentation.** It reports bootloader and boot state. A
  locked, verified device can still be running a debugger. Use it together with the local
  signals, not instead of them.
