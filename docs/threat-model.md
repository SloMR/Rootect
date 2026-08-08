# Threat model

What Rootect can promise, and what it cannot.

Two minutes, and it decides how you should use everything else.

## The short version

Rootect runs inside your app, on a device the attacker may own. Root means they have more
privilege than your app does. **No arrangement of on-device checks wins that argument**, and
any library claiming otherwise is overselling.

So Rootect does two achievable things instead:

1. **Raises cost.** Checks live in native code behind raw syscalls with no readable strings,
   so defeating them individually means reverse engineering rather than a one-line script.
2. **Moves the verdict off the device**, where the attacker's privilege does not reach.

## Who it actually stops

Be honest about which attacker you have, because the answer differs enormously.

| | Who | Result |
|---|---|---|
| **1** | Ordinary rooted user. Installed a root manager, maybe turned on hiding because an app complained. Does not write tooling. | **Usually detected** |
| **2** | Commodity fraud at scale — device farms, emulators, off-the-shelf hiding stacks, running unattended. | **Mostly detected**, and the economics hurt them more than any single check |
| **3** | Someone reverse engineering *your* app specifically. Will read this repository. | **Not detected by anything on the device** |

Most root-detection benchmarks quietly measure tier 1 and imply tier 3.

Against tier 3, only the attestation path constrains anything — and only if you verify it on
your server.

## Evidence versus proof

| | Trust |
|---|---|
| `signals`, `risk`, `score` | **Evidence.** Computed on the device, so editable by whoever owns it |
| Attestation chain verified **on your server** | **Proof.** Signed by secure hardware, tied to a challenge you issued |
| Attestation chain verified **on the device** | **Not proof.** It collapses to a local boolean, with all the weaknesses of one |

The difference is not check quality. It is who computes the answer. Anything decided on the
device is a claim the device makes about itself.

**Why the hardware path holds:** the attestation key lives in the device's secure element. It
cannot be extracted or used by software, however privileged. An attacker can withhold the
chain, or send an old or invented one — a server that checks the signature, the root, the
revocation list and its own challenge rejects all of those. And the hardware attests exactly
what you want to know: whether the bootloader is unlocked and verified boot passed. Rooting a
device effectively requires unlocking the bootloader, and the bootloader does not answer to
the OS running above it.

## Known limits

- **Local checks can be suppressed** by anything with enough privilege inside the process.
  This is inherent, not a bug to be fixed.
- **Actively hidden root defeats the filesystem signals.** `MAGISK_ARTIFACT` does not survive
  it, and the two candidate replacements were measured and do not work — see
  [signals.md](signals.md).
- **`isRooted` can be `false` on a rooted device.** Measured: `CRITICAL`, score 94,
  `isRooted = false`. Use `risk` and `score` — see [scoring.md](scoring.md).
- **Forged attestation exists.** Tools using leaked hardware keys can fake it. Revocation
  checking catches the known ones; a key nobody has reported yet still passes.
- **Some devices cannot attest at all.** Treat `ATTESTATION_SOFTWARE_ONLY` as *"could not
  verify"*, never as *"clean"*.
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

Rootect raises the cost of a bypass from trivial to genuinely difficult, and gives you a
hardware-signed statement your server can trust. It does not make a rooted phone tell the
truth.
