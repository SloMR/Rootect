package io.github.rootect.signal

/** How likely a signal is to be wrong. [weight] is a percentage used by the scorer. */
public enum class Confidence(internal val weight: Int) {
    /** Common on honest devices, e.g. a test-keys build. */
    WEAK(10),

    /** Unusual but explainable, e.g. an unused root manager. */
    MODERATE(25),

    /** Hard to explain away, e.g. an `su` binary. */
    STRONG(50),

    /** Maximum heuristic weight, not proof. A wrong expected signing hash scores 100 too. */
    CONCLUSIVE(100),
}
