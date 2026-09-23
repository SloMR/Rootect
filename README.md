<div align="center">

<img src="docs/assets/rootect-logo.png" alt="Rootect" width="180">

# Rootect

**Environment-integrity evidence for Android apps.**

Root, runtime instrumentation, repackaging, debuggers and emulators — reported as evidence
your app can weigh, not a verdict it has to accept.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](LICENSE)
[![API](https://img.shields.io/badge/API-24%2B-brightgreen?style=flat-square)](https://developer.android.com/tools/releases/platforms)
[![Dependencies](https://img.shields.io/badge/dependencies-stdlib%20only-2E7D32?style=flat-square)](docs/integration.md#install)

</div>

The Android library has no third-party dependencies — the Kotlin standard library and nothing
else. No permissions. No Google Play requirement. `minSdk 24`.

```kotlin
implementation("io.github.rootect:rootect-core:1.1.0")
```

```kotlin
val report = Rootect.analyze(context)

report.risk      // SAFE | LOW | MEDIUM | HIGH | CRITICAL
report.score     // 0..100
report.signals   // the evidence
```

## What it looks for

| | |
|---|---|
| **Root** | Visible Magisk, KernelSU and APatch artefacts and mounts; a legacy KernelSU kernel probe |
| **Instrumentation** | Frida, objection, Xposed / LSPosed, and inline hooks in our own code |
| **App integrity** | Repackaging, resigning, debuggable builds, unexpected installers |
| **Environment** | Unlocked bootloader, permissive SELinux, emulators, debuggers |
| **Hardware attestation** | A signed statement from the device's secure hardware, for your server to verify |

Filesystem and process probes use native code and raw syscalls with selected strings
XOR-hidden. Android API checks remain in Kotlin; a public API hook can replace the report.

## What it does not do

Rootect runs inside your app, on a device the attacker may own. **No on-device check survives
an attacker with enough privilege**, and any library claiming otherwise is overselling. What
Rootect does is harden individual probes and provide attestation evidence for independent
server verification:

```kotlin
val challenge = api.requestChallenge()              // from your server, used once
val chain = RootectAttestation.chain(challenge)     // signed by secure hardware
api.submitAttestation(challenge, chain, Rootect.analyze(context)) // server gates on the chain
```

The signing key normally stays in hardware. Your server validates the chain, revocation,
freshness and app identity before using it as evidence.
[How it works, and how to verify it →](docs/attestation.md)

## Honest limits

- Actively hidden root (DenyList + Shamiko) defeats the filesystem signals
- Current KernelSU and APatch kernel interfaces are not validated detection paths; see
  [signals.md](docs/signals.md)
- `isRooted` can read `false` on a rooted device; total scores are not proof of root either. See
  [scoring.md](docs/scoring.md)
- Attestation can be forged with leaked hardware keys; revocation checking catches the known
  ones
- Rooted is not the same as malicious, and blocking those users is a product decision with a
  real cost

Every signal is documented with **what defeats it** in [signals.md](docs/signals.md),
including three ideas that were built, measured, and did not work.

## Documentation

| | |
|---|---|
| [integration.md](docs/integration.md) | Full API, configuration, common mistakes |
| [attestation.md](docs/attestation.md) | Hardware-backed evidence and server verification |
| [signals.md](docs/signals.md) | Every signal, what it catches, and its limits |
| [scoring.md](docs/scoring.md) | How signals become a 0–100 score |
| [threat-model.md](docs/threat-model.md) | What Rootect can and cannot promise |

## Sample

```bash
./gradlew :sample:installDebug
```

A live dashboard of every signal plus a separate server-gated attestation card. The card
fails closed when the verifier is unavailable; the local dashboard remains diagnostic only.

## Building

Requires the Android NDK (`28.2.13676358`) and CMake. The Gradle daemon JVM is pinned by the
project, so a clone provisions it automatically.

```bash
./gradlew :rootect-core:test                       # unit tests
./gradlew :rootect-core:connectedDebugAndroidTest  # instrumented, needs a device
```

Native code builds for `arm64-v8a`, `armeabi-v7a` and `x86_64`. The emulator ABI stays in
that list deliberately — it is the false-positive control.

### Per-distribution native diversity

The published AAR is necessarily identical for every Maven consumer. A company or fork
that builds Rootect from source can give its native string obfuscation a distinct build
seed without changing code:

```bash
./gradlew :rootect-core:generateRootectObfuscationSeed -q
./gradlew :rootect-core:assembleRelease --project-prop=rootect.obfuscationSeed=0xYOURSEED
```

The seed is a diversity input, not a secret. Keep it stable for reproducible builds or
rotate it deliberately per release. Different seeds produce different native result tags
and encrypted strings, making byte-for-byte patches less reusable across apps; they do not
make an on-device detector impossible to reverse.

## License

[Apache 2.0](LICENSE)
