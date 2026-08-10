package io.github.rootect

import android.content.Context
import io.github.rootect.internal.attest.HardwareAttestation
import io.github.rootect.internal.detect.IntegrityDetector
import io.github.rootect.internal.detect.PackageDetector
import io.github.rootect.internal.detect.RuntimeDetector
import io.github.rootect.internal.jni.NativeBridge
import io.github.rootect.internal.jni.NativeSignals
import io.github.rootect.signal.Signal
import io.github.rootect.signal.SignalId
import kotlin.random.Random

/** Entry point for Rootect. */
public object Rootect {

    /** Runs every enabled detector and returns the evidence. */
    @JvmStatic
    @JvmOverloads
    public fun analyze(
        context: Context,
        config: RootectConfig = RootectConfig(),
    ): RootectReport {
        val signals = mutableListOf<Signal>()
        var inconclusive = 0

        // Each detector is isolated: a detection library must not be why a host app dies.
        // A wrong answer is evidence, a library that never loaded is only a packaging bug.
        if (!NativeBridge.available) {
            inconclusive++
        } else {
            try {
                val nonce = Random.nextInt()
                val scan = NativeBridge.scan(nonce)
                if (scan.size != 3 || scan[2] != NativeSignals.tagOf(scan[0], scan[1], nonce)) {
                    signals += Signal(SignalId.DETECTOR_TAMPERED)
                } else {
                    signals += NativeSignals.decode(scan[0])
                    inconclusive += scan[1]
                }
            } catch (_: UnsatisfiedLinkError) {
                inconclusive++
            } catch (_: Throwable) {
                signals += Signal(SignalId.DETECTOR_TAMPERED)
            }
        }

        try {
            signals += PackageDetector.detect(context)
        } catch (_: Throwable) {
            inconclusive++
        }

        try {
            signals += RuntimeDetector.detect()
        } catch (_: Throwable) {
            inconclusive++
        }

        try {
            signals += IntegrityDetector.detect(context, config)
        } catch (_: Throwable) {
            inconclusive++
        }

        // Opt-in: generating an attested key is slow. Compared against what the properties
        // claimed, because hardware contradicting them is stronger than either alone.
        if (config.hardwareAttestation) {
            try {
                val attestation = HardwareAttestation.attest()
                if (attestation == null) {
                    inconclusive++
                } else {
                    val propertiesSayLocked =
                        signals.none { it.id == SignalId.BOOTLOADER_UNLOCKED }
                    signals += HardwareAttestation.signals(attestation, propertiesSayLocked)
                }
            } catch (_: Throwable) {
                inconclusive++
            }
        }

        return RootectReport(signals.distinctBy { it.id }, inconclusive)
    }

    /** Convenience over [analyze] for callers who only want a boolean. */
    @JvmStatic
    public fun isRooted(context: Context): Boolean = analyze(context).isRooted
}
