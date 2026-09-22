package io.github.rootect

import android.content.Context
import android.os.Build
import io.github.rootect.internal.attest.HardwareAttestation
import io.github.rootect.internal.detect.IntegrityDetector
import io.github.rootect.internal.detect.PackageDetector
import io.github.rootect.internal.detect.RuntimeDetector
import io.github.rootect.internal.detect.SettingsDetector
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
        var bootStateRead = false
        var nativeSigning: Int? = null

        // Each detector is isolated: a detection library must not crash its host app.
        // A wrong answer is evidence; a library that never loaded is a packaging problem.
        if (!NativeBridge.available) {
            inconclusive++
        } else {
            try {
                val nonce = Random.nextInt()
                val scan = NativeBridge.scan(
                    nonce,
                    runCatching { context.applicationInfo.sourceDir }.getOrNull(),
                    config.expectedSigningSha256,
                    Build.VERSION.SDK_INT,
                )
                if (scan.size != 4 ||
                    scan[3] != NativeSignals.tagOf(scan[0], scan[1], scan[2], nonce)
                ) {
                    signals += Signal(SignalId.DETECTOR_TAMPERED)
                } else {
                    signals += NativeSignals.decode(scan[0])
                    inconclusive += scan[1]
                    bootStateRead = scan[2] and NativeSignals.FACT_BOOT_STATE_READ != 0
                    nativeSigning = when {
                        scan[2] and NativeSignals.FACT_SIGNING_MATCH != 0 -> 0
                        scan[2] and NativeSignals.FACT_SIGNING_MISMATCH != 0 -> 1
                        else -> null
                    }
                }
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
            signals += SettingsDetector.detect(context)
        } catch (_: Throwable) {
            inconclusive++
        }

        try {
            val integrity = IntegrityDetector.detect(context, config, nativeSigning)
            signals += integrity.signals
            inconclusive += integrity.inconclusive
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
                    val propertiesSayLocked = bootStateRead &&
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
