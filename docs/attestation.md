# Hardware attestation

Attestation is generated on the device too. The difference is that a backend can verify its
signed claims independently of the local report.

## Why it is different

Every other signal is the device describing itself. This one is the device's **secure
hardware** signing a statement with a normally non-exportable private key. Leaked keys and hardware implementation flaws remain
possible. Ask it to generate a key and it returns a certificate
chain describing the device it runs on, signed through an attestation chain.

That hardware is one of two things, and the attestation records which as its `securityLevel`:

- **TEE** — the *Trusted Execution Environment*, an isolated region of the **main processor**
  (ARM TrustZone). It shares silicon with Android but runs where Android cannot reach. This is
  what most phones have. It is *not* a separate chip.
- **StrongBox** — a tamper-resistant secure element or integrated secure enclave, such as Pixel’s Titan M.
  Stronger, but only on hardware that ships one.

Rootect does not request StrongBox explicitly; having Titan M does not imply its use here.
The local result uses the lower of the attestation and KeyMint security levels.

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

Leaf first, root last. Real output from a test device:

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

Chain length varies by vendor and provisioning method. One device produced 4 certificates;
another produced 5. Accept a bounded list rather than one fixed length, then walk to the end.

The current verifier supports a statement in the target leaf (not every valid Android chain shape) and
rejects an attestation extension on any issuer, preventing a signed-child extension attack.

### Samsung and other vendors

Rootect uses the standard [Android Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation)
API. A Samsung or other OEM device whose chain ends at a pinned Google root follows the same
verification path. A device using another root fails closed until your backend explicitly
adds and audits that trust anchor.

[Samsung Knox Enhanced Attestation](https://docs.samsungknox.com/dev/knox-attestation/enhanced-attestation-v3/)
is separate. It uses Samsung Attestation Keys, the Knox Warranty Bit, Samsung roots and a
Samsung attestation service. Rootect does not implement that proprietary flow.

A tested Samsung showed why this matters: standard Android attestation accepted its
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

Local parsing checks the nonce and extension shape, not signatures, roots or revocation.
Missing or unparseable evidence is inconclusive, not `ATTESTATION_SOFTWARE_ONLY`.

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
CA1* (P-384), used for signing from February 2026. Pin both. Recently provisioned devices use the newer one:
the Samsung above chains to it, and pinning only the older root would have rejected a
currently locked, Verified phone.

The authoritative lists are:

```
https://android.googleapis.com/attestation/root     # accepted roots
https://android.googleapis.com/attestation/status   # revoked keys
```

Use Google's maintained Kotlin verifier instead of maintaining another certificate parser.
Build [android/keyattestation](https://github.com/android/keyattestation) from reviewed
upstream source, vendor it or publish it internally, and rerun the attestation tests when
updating the verifier.

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
default revocation source caches Google's list for an hour, sets connect and read timeouts, keeps serving
the last good list through a transient Google outage, and returns HTTP 503 only when it has no
list recent enough to trust.

Google's `keyattestation` library performs the cryptographic verification offline: it uses
`GoogleTrustAnchors` and a supplied revoked-serial list. The example server still calls Google
to fetch that list, then caches it for an hour. During an outage, a warm cache can serve its
last good list for up to 24 hours from the successful fetch. This is an availability tradeoff:
a key newly added to Google's list can remain accepted while the cached list is stale. A cold
start without a list, or an expired staleness budget, returns HTTP 503 instead.

Google documents the [revocation feed's caching and revocation policy](https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status).
The possible delay before Google revokes a leaked key does not make additional staleness
risk-free. In production, refresh into a shared store from a background job, follow the feed's
`Cache-Control` header, and choose an explicit staleness budget for the host app's requirements.

### Root updates

The Kotlin server uses the verifier’s bundled `GoogleTrustAnchors`; it does not download
new trusted roots at runtime. When Google changes its [published roots](https://android.googleapis.com/attestation/root),
review and update the verifier source, run the server tests, then rebuild and redeploy the
server. Updating source alone does not update a running server. Revocation-list refresh
is separate and continues at runtime.

### Layered evidence: a hardware gate plus an untrusted runtime report

The two inputs cover different threats, so the sample sends both and the server keeps them
distinct:

- **The hardware chain is the authoritative gate.** It proves boot integrity — bootloader
  locked, verified boot, app identity, key origin, revocation — and `attestationTrusted`
  comes only from it.
- **The local Rootect report is untrusted, complementary evidence.** The chain is blind to
  *runtime* compromise — Frida/Xposed hooking, an attached debugger, a device's historical
  Knox tamper. The sample posts `isRooted` and a signal-name list beside the chain. A hooked
  client can forge both. The server returns well-formed names as `reportedSignals` and does
  not use them, or `isRooted`, to grant access.

An unrooted phone can have an unlocked bootloader. The server therefore does not infer
report tampering from `isRooted=false` plus unlocked/unverified boot. Its chain rejection
remains `attestation rejected`, regardless of the client’s root claim. Missing attestation
remains unknown, never a clean result.

An app backend can apply a policy *after* the verifier returns. For example:

```kotlin
enum class Access { ALLOW, STEP_UP, DENY }

fun decideAccess(verdict: AttestationVerdict, accountNeedsReview: Boolean): Access = when {
    !verdict.attestationTrusted -> Access.DENY
    accountNeedsReview -> Access.STEP_UP // Computed from server-side account data.
    verdict.reportedSignals.any {
        it == "FRIDA_LIBRARY_MAPPED" || it == "SIGNATURE_MISMATCH"
    } -> Access.STEP_UP
    else -> Access.ALLOW
}
```

The signal branch can only add friction: a hooked client can omit or forge every signal.
The hardware gate and any server-side account checks must stand on their own; missing
client telemetry must never be interpreted as proof of a clean runtime.

### Fail closed when the server is unavailable

Treat every state except an accepted server response as unable to access the protected operation:
not started, pending, timeout, malformed response, unavailable revocation data, missing
attestation, and rejected attestation. Clear any earlier approval before retrying so a stale green
result cannot survive a server outage.

The sample does this automatically. Its local Rootect dashboard remains available for
diagnostics, but the separate **Hardware attestation** card starts paused and contacts the backend
on launch. Only `attestationTrusted=true` changes that card to green and grants access. A rejection makes the separate **ATTESTATION** tile `REJECTED`, without changing
**LOCAL RISK**. A forged empty report can show `SAFE 0` beside rejected attestation. An
unreachable server shows yellow `UNVERIFIED` / `Server unavailable` and does not grant access.

The example has no protected backend operation or token; its access indicator is a demo.
That card is still UI inside an attacker-controlled process: Frida can repaint it or replace
its boolean. In a real app, the backend must enforce the decision by withholding the protected
data, token, or operation. Never send a protected secret first and ask the app to hide it after
a local check.

## What it looks like in practice

Same code, two devices, opposite answers:

| | Rooted phone | Samsung, current boot |
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

- **Forged attestation is real.** [TrickyStore](https://github.com/beakthoven/TrickyStoreOSS)
  re-signs the chain with a *leaked factory keybox*, so it validates against a real Google root.
  A leaked key can also forge claims about other devices; it is not limited to the
  device from which the key leaked. Revocation (step 4) rejects the leaked keys Google knows about, and
  [devices launching with Android 16 use RKP](https://developer.android.com/privacy-and-security/security-key-attestation)
  with no factory keybox to leak — but the pre-RKP installed base keeps its factory keys, so a
  keybox nobody has reported yet still passes. Revocation, not an OS cutoff, is the defense.
- **A nonce stops replay, not live relay.** Bind challenges to the account and transaction,
  rate-limit them, and treat clean-device proxying as backend fraud detection.
- **Not every device can attest.** Older and some low-end hardware returns nothing, or
  software-only attestation. Treat that as *"could not verify"*, never *"clean"*.
- **The root list changes.** Google added one in February 2026. A hardcoded pin will go stale
  — audit and update the upstream verifier’s bundled roots; this example does not
  refresh root certificates at runtime.
- **Attestation says nothing about instrumentation.** It reports bootloader and boot state. A
  locked, verified device can still be running a debugger. Use it together with the local
  signals, not instead of them.
