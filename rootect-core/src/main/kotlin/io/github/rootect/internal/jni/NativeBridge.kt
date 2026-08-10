package io.github.rootect.internal.jni

internal object NativeBridge {

    /**
     * False when the library could not be loaded
     */
    val available: Boolean = try {
        System.loadLibrary("rootect")
        true
    } catch (_: Throwable) {
        false
    }

    /** Runs every native check. Returns [flags, inconclusive, facts, tag]. */
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
