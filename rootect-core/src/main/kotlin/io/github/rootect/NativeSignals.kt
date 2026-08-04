package io.github.rootect

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
    )

    val count: Int get() = bits.size

    fun decode(flags: Int): List<Signal> =
        bits.filter { (bit, _) -> flags and bit != 0 }.map { (_, id) -> Signal(id) }
}
