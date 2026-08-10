package io.github.rootect.internal.jni

import io.github.rootect.signal.Signal
import io.github.rootect.signal.SignalId

// Bit contract with detectors.h. The order must match NativeSignal there; a debug test
// compares this list's size against nativeSignalCount() so drift fails loudly.
internal object NativeSignals {

    private val bits: List<Pair<Int, SignalId>> = listOf(
        (1 shl 0) to SignalId.SU_BINARY,
        (1 shl 1) to SignalId.MAGISK_ARTIFACT,
        (1 shl 2) to SignalId.SYSTEM_PARTITION_WRITABLE,
        (1 shl 3) to SignalId.KERNEL_ROOT_SYSCALL,
        (1 shl 4) to SignalId.BOOTLOADER_UNLOCKED,
        (1 shl 5) to SignalId.TEST_KEYS_BUILD,
        (1 shl 6) to SignalId.FRIDA_LIBRARY_MAPPED,
        (1 shl 7) to SignalId.FRIDA_THREAD_PRESENT,
        (1 shl 8) to SignalId.XPOSED_FRAMEWORK_PRESENT,
        (1 shl 9) to SignalId.CODE_SECTION_MODIFIED,
        (1 shl 10) to SignalId.TRACER_ATTACHED,
        (1 shl 11) to SignalId.EMULATOR_FINGERPRINT,
        (1 shl 12) to SignalId.SELINUX_PERMISSIVE,
    )

    val count: Int get() = bits.size
    const val FACT_BOOT_STATE_READ: Int = 1 shl 0

    /** Mirror of result_tag in detect_root.cpp. The two must stay identical. */
    fun tagOf(flags: Int, inconclusive: Int, facts: Int, nonce: Int): Int {
        // Hex with toInt() rather than a decimal literal: these are unsigned constants in
        // the C++ mirror, and hand-converting them to signed is how they drift apart.
        var x = nonce xor (flags * 0x9E3779B1.toInt()) xor ((inconclusive + 1) * 40503) xor
            ((facts + 1) * 0x85EBCA77.toInt())
        x = x xor (x ushr 15)
        x *= 0x2545F491
        x = x xor (x ushr 13)
        x *= 0x27D4EB2F
        x = x xor (x ushr 16)
        return x
    }

    /** Turns a native flags word into signals. */
    fun decode(flags: Int): List<Signal> =
        bits.filter { (bit, _) -> flags and bit != 0 }.map { (_, id) -> Signal(id) }
}
