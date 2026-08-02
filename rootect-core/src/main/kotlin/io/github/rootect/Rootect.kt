package io.github.rootect

/**
 * Entry point for Rootect.
 */
public object Rootect {

    init {
        System.loadLibrary("rootect")
    }

    /**
     * Round-trips a string through the native layer.
     */
    public external fun nativePing(): String
}
