package io.github.rootect

import android.content.Context

/**
 * Entry point for Rootect.
 */
public object Rootect {

    init {
        System.loadLibrary("rootect")
    }

    /** Runs every enabled detector and returns the evidence. */
    @JvmStatic
    public fun analyze(context: Context): RootectReport {
        val signals = mutableListOf<Signal>()
        return RootectReport(signals.toList())
    }

    @JvmStatic
    public fun isRooted(context: Context): Boolean = analyze(context).isRooted

    /** Temporary linkage probe. */
    public external fun nativePing(): String
}
