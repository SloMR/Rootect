# Signals

Every signal Rootect emits, what it catches, and where it stops.

The limits column is the point. A detection library that only lists strengths is asking to be
believed rather than checked. The recorded lab covers visible root, hidden root, a clean
emulator, and an unrooted device with a tripped Knox bit. This catalogue also includes
implemented checks without established positive coverage, notably the KernelSU kernel probe.

`SignalId` values are stable — safe to persist and send to a fraud backend. New ones get
added; existing ones are not renamed.

---

## Root

| Signal | Confidence | Catches | Limits |
|---|---|---|---|
| `SU_BINARY` | STRONG | `su` on system paths, via raw syscalls | Hiding tools unmount these paths for the target app |
| `MAGISK_ARTIFACT` | STRONG | Magisk, KernelSU and APatch mount entries and files | **Does not survive Magisk DenyList + Shamiko** |
| `SYSTEM_PARTITION_WRITABLE` | STRONG | Mounts at or below `/system`, `/vendor`, `/product`, `/system_ext` marked writable | Modern root is systemless and does not remount |
| `KERNEL_ROOT_SYSCALL` | CONCLUSIVE | A positive version from the legacy KernelSU-style `prctl` probe | No separate APatch supercall or newer KernelSU ioctl probe; Magisk does not implement it |
| `ROOT_MANAGER_PACKAGE` | MODERATE | Magisk, KernelSU or APatch manager app installed | Package hiding, renaming, or just uninstalling it |

Hidden root is the honest gap. When root is hidden from an app, the filesystem evidence
is gone, and two candidate replacements were built and measured and neither works on
current Android — see [Dead ends](#dead-ends). With root hidden from the test app,
`MAGISK_ARTIFACT` was silent and `isRooted` was false.
`ROOT_MANAGER_PACKAGE` remained because the manager app was still installed.

`ROOT_MANAGER_PACKAGE` carries a cost worth stating plainly. Package visibility on API 30+
means a library cannot ask whether an app is installed without naming it first, so the manager
package list ships as a `<queries>` block in the library manifest and merges into the host
app's. Selected native literals are XOR-hidden; this list and JVM-side signatures remain readable
in the APK. The alternatives were requesting `QUERY_ALL_PACKAGES`, which no
library should ask of its host, or dropping the signal — naming eight packages an attacker
already knows is the cheaper trade.

## OS posture

| Signal | Confidence | Catches | Limits |
|---|---|---|---|
| `SELINUX_PERMISSIVE` | STRONG | SELinux not enforcing | Not a root signal — custom ROMs run permissive legitimately |
| `BOOTLOADER_UNLOCKED` | STRONG | Three boot-state properties (including any non-green Verified Boot state) | Properties are rewritable on a rooted device |
| `KNOX_WARRANTY_BIT_TRIPPED` | STRONG | Samsung reports its persistent Knox warranty fuse as tripped | Samsung only; the local property is rewritable, so Knox server attestation is authoritative |
| `TEST_KEYS_BUILD` | WEAK | `ro.build.tags` containing `test-keys` (not a signature verification) | Common on honest custom ROMs, hence `WEAK` |
| `DEVELOPER_OPTIONS_ENABLED` | WEAK | The Developer options toggle is on, read from `Settings.Global` | Common on honest devices and one JVM hook from silent; posture only, never feeds `isRooted` |

These sit in `ENVIRONMENT` and never feed `isRooted`. A permissive, unlocked device is
evidence about the *device*, not proof of root.

`DEVELOPER_OPTIONS_ENABLED` is deliberately `WEAK`. Enabling Developer options is routine on
an honest phone, and the toggle is a `Settings.Global` read that one hook silences — so it
colours the score without ever carrying it. It fires on any device with the toggle on; the
negative control is that it goes silent the moment the setting reads off, verified on the
rooted test phone by toggling the flag both ways with `rootScore` and `isRooted` unchanged
either way. The clean Android 37 x86_64 emulator also passed with the setting off and on:
no root or hook evidence in either state, and no developer-options signal when off. A
setting that was never written reads as off, as Android's own reader treats it; only a
denied read counts as inconclusive. One regression deletes the setting on a lab device and
restores it; the other fakes a denied read against a baseline that answered.

`SELINUX_PERMISSIVE` requires a readable enforcement-file line beginning with `0`.
A successful read of `1` does not fire. A denied read is not proof of enforcing mode; the
current implementation silently ignores errors after the initial path probe.

## Instrumentation

| Signal | Confidence | Catches | Limits |
|---|---|---|---|
| `FRIDA_LIBRARY_MAPPED` | STRONG | Known instrumentation libraries in our memory map | Renamed or anonymously-loaded agents |
| `FRIDA_THREAD_PRESENT` | STRONG | `gum-js-loop` and `pool-frida` threads in our process | Renamed threads |
| `XPOSED_FRAMEWORK_PRESENT` | STRONG | Xposed and LSPosed | Module-level hiding |
| `CODE_SECTION_MODIFIED` | CONCLUSIVE | Our own machine code differing from the file on disk | Instrumentation that sits above the native layer |
| `DETECTOR_TAMPERED` | STRONG | The native layer loaded but failed or returned an invalid result checksum | A targeted hook can reproduce the build-specific checksum; failure to load is only inconclusive |

`CODE_SECTION_MODIFIED` is the sturdiest of these: it compares eligible readable executable mappings for the
backing path containing its native marker against that file, so it catches the *modification* rather than the
brand, and renaming a tool does not help. It is also the check most dangerous to get wrong —
an early version fired on every 32-bit device because of an offset bug, which is the sort of
thing this page exists to admit.

`FRIDA_THREAD_PRESENT` matches prefixes `gum-js-loop` and `pool-frida`; these names are not reserved to Frida. It also starts a
GLib loop, whose `gmain` and `gdbus` threads look tempting — but any app embedding GStreamer
or another GLib consumer has those too, and flagging a host app for its own dependency is
precisely the false positive that gets a detection library removed.

## Debuggers

| Signal | Confidence | Catches | Limits |
|---|---|---|---|
| `TRACER_ATTACHED` | STRONG | A tracer holding our process, read from `TracerPid` | Attaching after the scan; Frida detaches ptrace once injected, so it reads 0 |
| `DEBUGGER_ATTACHED` | MODERATE | A JDWP debugger on the process | A JVM check, so one hook disables it; ordinary during development, hence `MODERATE` |

## App integrity

| Signal | Confidence | Catches | Limits |
|---|---|---|---|
| `SIGNATURE_MISMATCH` | CONCLUSIVE | PackageManager reports a different current signer, or a readable APK Signing Block reports a different signer | Needs the right expected hash. Unreadable or unsupported APK signing formats are inconclusive. Both checks run in the app process and can be hooked; the native parser does not verify APK signatures |
| `DEBUGGABLE_BUILD` | MODERATE | The app marked debuggable | Your own debug builds trip this legitimately |
| `UNTRUSTED_INSTALLER` | WEAK | Installed from an unexpected source | Sideloading is normal for independently distributed apps |

## Emulator

| Signal | Confidence | Catches | Limits |
|---|---|---|---|
| `EMULATOR_FINGERPRINT` | STRONG | QEMU device nodes and emulator hardware names | Emulators built to hide, which analysis environments are |

## Hardware attestation

Opt-in hardware evidence for off-device validation. Local parsing does not verify certificate
signatures, trusted roots or revocation. Local attestation signals remain
hookable; the server path is authoritative. See [attestation.md](attestation.md).

| Signal | Confidence | Catches |
|---|---|---|
| `ATTESTATION_BOOT_UNVERIFIED` | STRONG | Secure hardware reporting an unlocked or unverified device |
| `ATTESTATION_SOFTWARE_ONLY` | MODERATE | A parsed record reports a software security level; unavailable evidence is inconclusive instead |
| `ATTESTATION_CONTRADICTS_PROPERTIES` | CONCLUSIVE | Properties claiming a locked device while hardware disagrees |

`ATTESTATION_CONTRADICTS_PROPERTIES` needs the device to have actually claimed something.
Several `ro.boot.*` properties are readable only by system apps on newer Android, and some
OEMs never set them, so an app can easily get no answer at all — and "said nothing" is not
"said locked". The native scan reports whether the boot state was readable, and the
contradiction is only raised when it was. Without that distinction an honest device with an
unlocked bootloader and unreadable properties would be accused, at `CONCLUSIVE` confidence, of
actively rewriting them.

Known limit: tools exist that forge attestation using leaked hardware keys. Checking Google's
revocation list catches listed keys, subject to the verifier’s cache freshness, and is why
`attestation-server/src/main/kotlin/io/github/rootect/attestation/AttestationServer.kt` does it.

---

## Dead ends

Ideas that sound right, were built, measured, and do not work. Recorded so nobody spends a
weekend rediscovering them.

**Mount namespace divergence.** Compare our mount table against init's, since hiding tools
unmount only in the app's namespace. Modern Android hides other processes' `/proc` entries
in the tested configuration — the app saw only itself, leaving no usable comparison.

**Property tampering.** Catch rewritten properties by their modification counter, which the
Bionic property implementation maintains. Rewriting a read-only property recreates the entry instead of
updating it, so the counter reads zero, identical to an untouched device. The fallback,
comparing against the on-disk build properties, fails because that file is root-only.

**Instrumentation server port.** Connect to the default port an instrumentation server
listens on. It works, but requires the `INTERNET` permission, which a library must never
demand of its host — and a non-default port defeats it entirely. The permission-free
alternative is blocked by SELinux on enforcing devices.

These were designed and then **removed from `SignalId`** rather than shipped as values that
could never fire. A signal you can enumerate is a capability being claimed.

---

## How this was checked

| Environment | Result |
|---|---|
| Clean emulator | No root signals — the false-positive control |
| Unrooted phone, Knox warranty bit tripped | No current-root or hook signal; `KNOX_WARRANTY_BIT_TRIPPED`; Android attestation accepts current boot |
| Rooted phone | `CRITICAL`, root and posture signals |
| Rooted phone, root hidden from the test app | `MAGISK_ARTIFACT` silent; `ROOT_MANAGER_PACKAGE` remained; `isRooted` false |
| Instrumented process | Instrumentation signals fire |
| Resigned APK | `SIGNATURE_MISMATCH` fires |
| APK with an original v3 signer and rotated v3.1 signer | On two Android 13+ devices, the native check matched the current rotated certificate, rejected the original certificate, and the sample emitted no `SIGNATURE_MISMATCH` |
| Repacked app on an unrooted phone | `FRIDA_THREAD_PRESENT` and `SIGNATURE_MISMATCH` fire; server rejects signer |

The clean-device run is half the evidence. A check that flags everything passes the rooted
test perfectly and is worthless.
