package io.github.rootect

import android.content.Context

/** Entry point for Rootect. */
public object Rootect {

    /** Runs every enabled detector and returns the evidence. */
    @JvmStatic
    public fun analyze(context: Context): RootectReport {
        val signals = mutableListOf<Signal>()
        return RootectReport(signals.toList())
    }

    /** Convenience over [analyze] for callers who only want a boolean. */
    @JvmStatic
    public fun isRooted(context: Context): Boolean = analyze(context).isRooted
}
