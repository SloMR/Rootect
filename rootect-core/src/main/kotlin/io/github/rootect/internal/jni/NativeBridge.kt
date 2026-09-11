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
}
