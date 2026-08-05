#pragma once

// Detection built on the primitives in syscalls.h / proc.h / obfuscate.h.

namespace rootect {

// Bit positions are a contract with NativeSignals.kt. Adding one means adding it there
// too; `nativeSignalCount` exists so a debug test fails if the two sides drift.
enum NativeSignal : unsigned {
    NS_SU_BINARY = 1u << 0,
    NS_MAGISK_ARTIFACT = 1u << 1,
    NS_SYSTEM_WRITABLE = 1u << 2,
    NS_KERNEL_ROOT_SYSCALL = 1u << 3,
    NS_BOOTLOADER_UNLOCKED = 1u << 4,
    NS_TEST_KEYS_BUILD = 1u << 5,
    NS_FRIDA_LIBRARY = 1u << 6,
    NS_FRIDA_THREAD = 1u << 7,
    NS_XPOSED_FRAMEWORK = 1u << 8,
    NS_CODE_MODIFIED = 1u << 9,
    NS_TRACER_ATTACHED = 1u << 10,
    NS_EMULATOR = 1u << 11,
};

constexpr unsigned kNativeSignalCount = 12;

struct ScanOutcome {
    unsigned flags = 0;

    // Probes that could not complete — a denied read, or a /proc line too long to parse.
    // Not evidence of anything; recorded so "found nothing" is never confused with
    // "could not look".
    unsigned inconclusive = 0;
};

void scan_root(ScanOutcome& out);
void scan_hooks(ScanOutcome& out);
void scan_emulator(ScanOutcome& out);

// Mixes a scan result with a caller-supplied nonce. Kotlin re-derives this and treats a
// mismatch as evidence, so replacing the JNI entry point is no longer free.
unsigned result_tag(unsigned flags, unsigned inconclusive, unsigned nonce);

ScanOutcome scan_all();

} // namespace rootect
