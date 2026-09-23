# Integration

How to add Rootect to an app and use every part of it.

For the hardware-backed path, see [attestation.md](attestation.md). For what any of this is
worth against a real attacker, see [threat-model.md](threat-model.md).

## Install

```kotlin
// build.gradle.kts
dependencies {
    implementation("io.github.rootect:rootect-core:1.0.0")
}
```

No third-party dependencies — the published POM pulls in the Kotlin standard library and
nothing else. No permissions, no Google Play requirement. `minSdk 24`. Native code ships for
`arm64-v8a`, `armeabi-v7a` and `x86_64`.

R8 and ProGuard need no configuration — the required keep rules ship inside the artifact as
consumer rules.

### Per-app native diversification

Every app using the published Maven AAR receives the same precompiled native library. If
you need a company- or app-specific binary, build Rootect from source and pass a distinct
32-bit seed:

```bash
./gradlew :rootect-core:generateRootectObfuscationSeed -q
./gradlew :rootect-core:assembleRelease --project-prop=rootect.obfuscationSeed=0xYOURSEED
```

You can also set `ROOTECT_OBFUSCATION_SEED` in CI. The accepted forms are decimal or
`0x`-prefixed hexadecimal; Gradle normalises either to eight hexadecimal digits before
passing it to CMake. The seed is not secret—it diversifies the result tag and hidden-string
ciphertext, so source-built native binaries differ between distributions.

## Quick start

```kotlin
val report = Rootect.analyze(context)

if (report.risk >= RiskLevel.HIGH) {
    // your policy here
}
```

That is the whole integration. Everything below is detail.

## The API

### `Rootect`

```kotlin
Rootect.analyze(context): RootectReport
Rootect.analyze(context, config): RootectReport
Rootect.isRooted(context): Boolean
```

`analyze` runs every enabled detector and returns the evidence. Detector failures are caught,
but this cannot guarantee protection against every exception or native crash. Missing native
code is inconclusive; a failure after loading emits `DETECTOR_TAMPERED`. Some inner errors
are suppressed, so zero inconclusive checks does not mean every probe completed.

`isRooted(context)` is a convenience wrapper. Read the warning under
[Rollups](#rollups-and-their-trap) before using it.

### `RootectReport`

```kotlin
report.risk                  // SAFE | LOW | MEDIUM | HIGH | CRITICAL
report.score                 // 0..100
report.signals               // List<Signal>, deduplicated by id
report.inconclusiveChecks    // probes that could not complete
report.inconclusiveSources   // Set<InconclusiveCheck>: which checks could not complete

report.scoreFor(Category.ROOT)   // 0..100 for one category
report.signalsIn(Category.ROOT)  // that category's evidence

report.isRooted              // rollups, per category
report.isHooked
report.isTampered
report.isEmulator
report.isDebugged
```

How `score` is calculated is in [scoring.md](scoring.md). It is worth five minutes.

### `Signal`

```kotlin
signal.id           // SignalId - stable, safe to persist
signal.category     // ROOT | ENVIRONMENT | HOOK | DEBUG | TAMPER | EMULATOR
signal.confidence   // WEAK | MODERATE | STRONG | CONCLUSIVE
```

A signal carries an id and nothing else. There is deliberately no field describing *which*
file or check matched: that information is free reconnaissance for an attacker, and it
belongs in your own server logs rather than in the app.

`SignalId` values are stable. New ones get added over time; existing ones are never renamed,
so they are safe to persist and ship to a fraud backend. Handle unknown values gracefully —
a `when` over `SignalId` should have an `else`.

Every signal, what it catches and where it fails is in [signals.md](signals.md).

## Configuration

```kotlin
Rootect.analyze(
    context,
    RootectConfig(
        expectedSigningSha256 = BuildConfig.SIGNING_SHA256,
        trustedInstallers = setOf("com.android.vending"),
        hardwareAttestation = true,
    ),
)
```

### `expectedSigningSha256`

SHA-256 of your release signing certificate, hex, colons optional. Without it,
`SIGNATURE_MISMATCH` can never fire and this signing-certificate check is disabled.

The sample accepts it as `-Prootect.sampleSigningSha256=<64-hex>`.

**Generate it at build time.** The `signingCertSha256()` helper below is pseudocode for your
build’s certificate lookup, not a function supplied by Rootect. A pasted constant becomes wrong the day you rotate keys, and
then every honest install reports itself repackaged with `CONCLUSIVE` confidence:

```kotlin
// app/build.gradle.kts
android {
    buildFeatures { buildConfig = true }
    defaultConfig {
        buildConfigField("String", "SIGNING_SHA256", "\"${signingCertSha256()}\"")
    }
}
```

`PackageManager` reads the first current signer in `apkContentsSigners`. Native code reads
the APK Signing Block and hashes the certificate of the signer the platform would pick for
this Android version (v3.1, then v3, then v2). Either one disagreeing with your hash raises
`SIGNATURE_MISMATCH`; a channel that cannot be read counts as inconclusive, not as a
mismatch. One expected hash cannot accept several delivery certificates.

### `trustedInstallers`

Defaults to `com.android.vending` and `com.google.android.feedback`. Anything
else emits `UNTRUSTED_INSTALLER` at `WEAK` confidence.

**Override this if you distribute outside Play.** Enterprise, direct download and regional
stores are all normal, and the default will flag every one of your users. Pass the installers
you expect, or an empty set to accept anything.

### `hardwareAttestation`

Off by default. When on, `analyze` asks the secure hardware to attest boot state and emits
the `ATTESTATION_*` signals.

It generates a key, so it is **slow** — call it on considered checks, not on every screen.
And its result is still computed locally: for a verdict you can trust, do the round trip in
[attestation.md](attestation.md).

## Calling it

**Where.** Anywhere with a `Context`. Run the synchronous scan on a worker thread.

**Cost.** Scans perform file and Android API I/O, including mapped-code reads. Measure latency
on your target devices; attestation adds key generation.

**Threading.** `analyze` is synchronous and does file I/O. Keep it off the main thread,
including scans without attestation.

**How often.** Conditions change while an app runs — a debugger attaches, a framework loads.
One scan at startup tells you about startup. Re-scan at the moments that matter to you.

## Java

The API is Java-callable:

```java
RootectReport report = Rootect.analyze(context);

RootectConfig config = new RootectConfig(
        "AB:CD:…", RootectConfig.DEFAULT_TRUSTED_INSTALLERS, true);
RootectReport full = Rootect.analyze(context, config);
```

`RootectConfig` has no Java builder. Its arguments are positional and each has a default, so
you can stop after the ones you need — `new RootectConfig("AB:CD:…")` is valid.

## Responding to evidence

- **Choose total or category scores according to your policy.** Neither proves compromise.
- **Prefer degrading to blocking.** A false positive that blocks a paying customer usually
  costs more than a true positive you only logged. Rooted users are not automatically
  attackers.
- **Do not show the user what you detected.** Naming the signal that fired tells an attacker
  which check to look at next. Log the `SignalId` server-side.
- **Choose your own thresholds.** `RiskLevel` bands are a starting point. A bank and a puzzle
  game should not use the same cut-off.
- **Treat `inconclusiveChecks > 0` as uncertainty.** Use `inconclusiveSources` to distinguish,
  for example, a signing check from a process maps read. The names identify checks, not the
  underlying error; a denied read and a truncated file may share the same name.

### Rollups and their trap

The rollups are per-category thresholds, and they are deliberately conservative. Measured on
a rooted phone with root actively hidden:

```
risk = CRITICAL   score = 94   isRooted = false
```

Nothing is broken. The hiding tool removed the root-specific evidence, so the `ROOT` category
scored below threshold — while an unlocked bootloader and permissive SELinux still fired,
which is why overall risk is `CRITICAL`.

**A high total can reflect legitimate posture; a low total can still miss hidden root.**

## Common mistakes

| Mistake | Why it hurts |
|---|---|
| Branching on `isRooted` | Reads `false` on a device scoring 94 |
| Treating "no signals" as clean | Check `inconclusiveChecks` first |
| Pasting a signing hash by hand | Silently wrong after key rotation |
| Leaving `trustedInstallers` default when not on Play | Flags every legitimate user |
| Verifying attestation on the device | Collapses to a local boolean |
| Deciding locally on anything that matters | See [threat-model.md](threat-model.md) |

## Trying it

```bash
./gradlew :sample:installDebug
```

The sample is a live dashboard of every signal and a server-gated attestation example. Local
findings remain diagnostic; the access indicator stays denied until a fresh chain is accepted.
The backend example has no protected operation or token; real access must be enforced there. It also remembers root detection and real server rejection as two encrypted,
installation-local flags. This survives an ordinary restart, but root, reinstall, deletion, or
rollback can defeat it; keep the authoritative history on your backend. See
[attestation.md](attestation.md) before copying that flow.
