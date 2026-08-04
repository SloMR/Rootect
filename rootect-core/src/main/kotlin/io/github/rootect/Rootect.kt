package io.github.rootect

import android.content.Context

/** Entry point for Rootect. */
public object Rootect {

    /** Runs every enabled detector and returns the evidence. */
    @JvmStatic
    public fun analyze(context: Context): RootectReport {
        val signals = mutableListOf<Signal>()
        var inconclusive = 0

        // Each detector is isolated: a detection library must not be why a host app dies.
        try {
            val scan = NativeBridge.scan()
            signals += NativeSignals.decode(scan[0])
            inconclusive += scan[1]
        } catch (_: Throwable) {
            inconclusive++
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

        return RootectReport(signals.distinctBy { it.id }, inconclusive)
    }

    /** Convenience over [analyze] for callers who only want a boolean. */
    @JvmStatic
    public fun isRooted(context: Context): Boolean = analyze(context).isRooted
}
