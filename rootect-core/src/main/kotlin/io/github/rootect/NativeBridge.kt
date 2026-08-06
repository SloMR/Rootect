package io.github.rootect

internal object NativeBridge {

    init {
        System.loadLibrary("rootect")
    }

    /** Runs every native check. Returns [flags, inconclusive, tag]. */
    external fun scan(nonce: Int): IntArray

    /** Debug builds only. */
    external fun selfTest(): Boolean

    /** Debug builds only. Returns [error, truncated, lines]. */
    external fun parserProbe(path: String): IntArray

    /** Debug builds only. 0 if reachable, else -errno. */
    external fun pathProbe(path: String): Int

    /** Debug builds only. Returns [found, serial, valueLen] for a system property. */
    external fun propProbe(name: String): IntArray

    /** Debug builds only. How many signal bits the native side defines. */
    external fun nativeSignalCount(): Int
}
