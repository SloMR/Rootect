# Signals

Every signal Rootect emits, what it catches, and where it stops.

The limits column is the point. A detection library that only lists strengths is asking to be
believed rather than checked. Everything here was run on a rooted Pixel 5 and a clean
emulator; nothing is listed as working that has not been observed working.

`SignalId` values are stable — safe to persist and send to a fraud backend. New ones get
added; existing ones are not renamed.

---

## Root

| Signal | Confidence | Catches | Limits |
|---|---|---|---|
| `SU_BINARY` | STRONG | `su` or `busybox` on system paths, via raw syscalls | Hiding tools unmount these paths for the target app |
| `MAGISK_ARTIFACT` | STRONG | Magisk, KernelSU and APatch mount entries and files | **Does not survive Magisk DenyList + Shamiko** |
| `SYSTEM_PARTITION_WRITABLE` | STRONG | `/system`, `/vendor`, `/product` mounted writable | Modern root is systemless and does not remount |
| `KERNEL_ROOT_SYSCALL` | CONCLUSIVE | A kernel answering a root framework's private syscall | Kernel-side frameworks only; Magisk is not one |
| `ROOT_MANAGER_PACKAGE` | MODERATE | Magisk, KernelSU or APatch manager app installed | Package hiding, renaming, or just uninstalling it |

Hidden root is the honest gap. When Magisk actively hides from an app, the filesystem
evidence is gone, and two candidate replacements were built and measured and neither works on
current Android — see [Dead ends](#dead-ends).

## OS posture

| Signal | Confidence | Catches | Limits |
|---|---|---|---|
| `SELINUX_PERMISSIVE` | STRONG | SELinux not enforcing | Not a root signal — custom ROMs run permissive legitimately |
| `BOOTLOADER_UNLOCKED` | STRONG | Verified Boot state, read three ways | Properties are rewritable on a rooted device |
| `TEST_KEYS_BUILD` | WEAK | An OS not signed with a vendor release key | Common on honest custom ROMs, hence `WEAK` |

These sit in `ENVIRONMENT` and never feed `isRooted`. A permissive, unlocked device is
evidence about the *device*, not proof of root.

`SELINUX_PERMISSIVE` is detected in a non-obvious way. Policy denies ordinary apps read
access to the enforcement flag, so **the read succeeding is itself the finding** — a device
that hands over the bytes is not enforcing denials. Checking that the file merely exists
proves nothing; it exists either way.

## Instrumentation

| Signal | Confidence | Catches | Limits |
|---|---|---|---|
| `FRIDA_LIBRARY_MAPPED` | STRONG | Known instrumentation libraries in our memory map | Renamed or anonymously-loaded agents |
| `FRIDA_THREAD_PRESENT` | STRONG | Thread names belonging to instrumentation runtimes | Renamed threads |
| `XPOSED_FRAMEWORK_PRESENT` | STRONG | Xposed and LSPosed | Module-level hiding |
| `CODE_SECTION_MODIFIED` | CONCLUSIVE | Our own machine code differing from the file on disk | Instrumentation that sits above the native layer |
| `TRACER_ATTACHED` | STRONG | A debugger or tracer on our process | Attaching after the scan |
| `DETECTOR_TAMPERED` | STRONG | The native layer loaded but answering incorrectly | — |

`CODE_SECTION_MODIFIED` is the sturdiest of these: it compares every executable page of the
library against the file it was mapped from, so it catches the *modification* rather than the
brand, and renaming a tool does not help. It is also the check most dangerous to get wrong —
an early version fired on every 32-bit device because of an offset bug, which is the sort of
thing this page exists to admit.

## App integrity

| Signal | Confidence | Catches | Limits |
|---|---|---|---|
| `SIGNATURE_MISMATCH` | CONCLUSIVE | The APK resigned, therefore repackaged | Only works if you supply your expected signing hash |
| `DEBUGGABLE_BUILD` | MODERATE | The app marked debuggable | Your own debug builds trip this legitimately |
| `UNTRUSTED_INSTALLER` | WEAK | Installed from an unexpected source | Sideloading is normal for independently distributed apps |

## Emulator

| Signal | Confidence | Catches | Limits |
|---|---|---|---|
| `EMULATOR_FINGERPRINT` | STRONG | QEMU device nodes and emulator hardware names | Emulators built to hide, which analysis environments are |

## Hardware attestation

Opt-in, and the only group whose verdict does not depend on the device being honest — because
you check it on your server. See [integration.md](integration.md).

| Signal | Confidence | Catches |
|---|---|---|
| `ATTESTATION_BOOT_UNVERIFIED` | STRONG | Secure hardware reporting an unlocked or unverified device |
| `ATTESTATION_SOFTWARE_ONLY` | MODERATE | No hardware-backed attestation available |
| `ATTESTATION_CONTRADICTS_PROPERTIES` | CONCLUSIVE | Properties claiming a locked device while hardware disagrees |

Known limit: tools exist that forge attestation using leaked hardware keys. Checking Google's
revocation list catches the ones Google knows about, which is most of them, and is why
`scripts/verify-attestation.py` does it.

---

## Dead ends

Ideas that sound right, were built, measured, and do not work. Recorded so nobody spends a
weekend rediscovering them.

**Mount namespace divergence.** Compare our mount table against init's, since hiding tools
unmount only in the app's namespace. Modern Android hides other processes' `/proc` entries
from apps — an app can see exactly one process, its own. There is nothing to compare against.

**Property tampering.** Catch rewritten properties by their modification counter, which the
kernel bumps on every write. Rewriting a read-only property recreates the entry instead of
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
| Rooted Pixel 5 | `CRITICAL`, root and posture signals |
| Rooted, root actively hidden | `MAGISK_ARTIFACT` does not fire |
| Instrumented process | Instrumentation signals fire |
| Resigned APK | `SIGNATURE_MISMATCH` fires |

The clean-device run is half the evidence. A check that flags everything passes the rooted
test perfectly and is worthless.
