# Threat model

What Rootect can promise, and what it cannot.

Two minutes, and it decides how you should use everything else.

## The short version

Rootect runs inside your app, on a device the attacker may own. Root means they have more
privilege than your app does. **No arrangement of on-device checks wins that argument**, and
any library claiming otherwise is overselling.

So Rootect does two achievable things instead:

1. **Raises cost.** Selected probes use native syscalls and XOR-hidden literals. A hook on
   the public Kotlin API can still replace the entire report.
2. **Moves the verdict off the device**, where the attacker's privilege does not reach.

## Who it actually stops

Be honest about which attacker you have, because the answer differs enormously.

| | Who | Result |
|---|---|---|
| **1** | Ordinary rooted user. Installed a root manager, maybe turned on hiding because an app complained. Does not write tooling. | Visible artefacts may be detected; hiding can defeat them |
| **2** | Commodity fraud at scale — device farms, emulators, off-the-shelf hiding stacks, running unattended. | No population-wide detection rate has been established |
| **3** | Someone reverse engineering *your* app specifically. Will read this repository. | Can bypass local results; no guaranteed detection |

Most root-detection benchmarks quietly measure tier 1 and imply tier 3.

Against tier 3, only the attestation path constrains anything — and only if you verify it on
your server.

## Evidence versus proof

| | Trust |
|---|---|
| `signals`, `risk`, `score` | **Evidence.** Computed on the device, so editable by whoever owns it |
| Attestation chain verified **on your server** | **Cryptographic evidence.** Hardware-signed, app-bound and revocation-checked |
| Attestation chain verified **on the device** | **Not proof.** It collapses to a local boolean, with all the weaknesses of one |

The difference is not check quality. It is who computes the answer. Anything decided on the
device is a claim the device makes about itself.

**Why the hardware path helps:** the attestation key normally remains in secure hardware. A
server checks the path, revocation, app identity, challenge and boot state. Leaked keys,
implementation flaws and live relay remain possible, so this is strong evidence rather than
an absolute guarantee.

## Known limits

- **Local checks can be suppressed** by anything with enough privilege inside the process.
  This is inherent, not a bug to be fixed.
- **Actively hidden root defeats the filesystem signals.** `MAGISK_ARTIFACT` does not survive
  it, and the two candidate replacements were measured and do not work — see
  [signals.md](signals.md).
- **`isRooted` can be `false` on a rooted device.** Measured: `CRITICAL`, score 94,
  `isRooted = false`. Neither total nor category scores prove root — see [scoring.md](scoring.md).
- **Forged attestation exists.** Leaked factory keys can fake a chain; revocation catches
  known keys. [Devices launching with Android 16 use remote provisioning](https://developer.android.com/privacy-and-security/security-key-attestation)
  instead of factory attestation keys. An OS upgrade alone does not retire an older device's
  factory keys, and an unrevoked leaked key can still pass verification.
- **Live relay exists.** A nonce blocks replay, but a clean device can answer a fresh request
  in real time. Bind challenges to the account and action, then rate-limit and correlate them.
- **Some devices cannot attest at all.** Generation failure is inconclusive; a parsed software
  record emits `ATTESTATION_SOFTWARE_ONLY`. Neither means *"clean"*.
- **Rooted is not malicious.** Developers, researchers and privacy-minded people root their
  phones. Blocking them is a product decision with a real cost, and it is yours, not the
  library's.

## Assumptions

- The host app is not itself hostile. Rootect protects an app from its environment, not a
  user from the app.
- Attestation is verified on infrastructure the attacker does not control. With no backend,
  you have evidence and little more.
- **The attacker has read the source.** It is open source; assume that. Nothing here depends
  on checks being secret — only on them being individually expensive, and on the attestation
  path being cryptographic rather than obscure.

## One sentence

Rootect raises bypass cost and supplies hardware-signed evidence for server policy. It does
not make a rooted phone tell the truth.
