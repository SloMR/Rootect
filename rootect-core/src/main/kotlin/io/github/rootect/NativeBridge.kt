package io.github.rootect

internal object NativeBridge {

    init {
        System.loadLibrary("rootect")
    }

    external fun selfTest(): Boolean

    /** Debug builds only. Returns [error, truncated, lines]. */
    external fun parserProbe(path: String): IntArray

    /** Debug builds only. 0 if reachable, else -errno. */
    external fun pathProbe(path: String): Int
}
