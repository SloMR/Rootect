package io.github.rootect.internal.detect

import android.os.Debug
import io.github.rootect.signal.Signal
import io.github.rootect.signal.SignalId

// Checks that only exist on the JVM side. Both are easily defeated on their own — they
// complement the native scans rather than standing in for them.
internal object RuntimeDetector {

    private val XPOSED_CLASSES = listOf(
        "de.robv.android.xposed.XposedBridge",
        "de.robv.android.xposed.XposedHelpers",
        "de.robv.android.xposed.IXposedHookLoadPackage",
    )

    /** Emits debugger and Xposed signals. */
    fun detect(): List<Signal> {
        val signals = mutableListOf<Signal>()

        // Ordinary during development, hence MODERATE.
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            signals += Signal(SignalId.DEBUGGER_ATTACHED)
        }

        // Xposed leaves its bridge classes loadable in every hooked process.
        val xposedLoaded = XPOSED_CLASSES.any { name ->
            try {
                Class.forName(name, false, RuntimeDetector::class.java.classLoader)
                true
            } catch (_: Throwable) {
                false
            }
        }
        if (xposedLoaded) signals += Signal(SignalId.XPOSED_FRAMEWORK_PRESENT)

        return signals
    }
}
