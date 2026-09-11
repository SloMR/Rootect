package io.github.rootect.internal.jni

/** Debug-only native probes; in the `debug` source set, so they never reach the release AAR. */
internal object NativeProbes {

    // Touching NativeBridge loads librootect before any probe binds.
    @Suppress("unused")
    private val loaded = NativeBridge.available

    /** Proves the raw syscalls work on this ABI and a hidden string decoded byte-exact. */
    external fun selfTest(): Boolean

    /** Returns [error, truncated, lines] for for_each_line over a fixture. */
    external fun parserProbe(path: String): IntArray

    /** 0 if reachable, else -errno. */
    external fun pathProbe(path: String): Int

    /** Returns [found, serial, valueLen] for a system property. */
    external fun propProbe(name: String): IntArray

    /** How many signal bits the native side defines. */
    external fun nativeSignalCount(): Int

    /** Instrumentation flags scan_maps would set for a mapped file path. */
    external fun mapsProbe(path: String): Int
}
