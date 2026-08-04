#pragma once

// Root detection built on the primitives in syscalls.h / proc.h / obfuscate.h.

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
};

constexpr unsigned kNativeSignalCount = 6;

struct ScanOutcome {
    unsigned flags = 0;

    // Probes that could not complete — a denied read, or a /proc line too long to parse.
    // Not evidence of anything; recorded so "found nothing" is never confused with
    // "could not look".
    unsigned inconclusive = 0;
};

ScanOutcome scan_root();

} // namespace rootect
