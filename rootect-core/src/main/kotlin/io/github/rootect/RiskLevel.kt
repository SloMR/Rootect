package io.github.rootect

/** [RootectReport.score] banded. */
public enum class RiskLevel {
    /** Nothing found. */
    SAFE,

    /** 1..24 */
    LOW,

    /** 25..49 */
    MEDIUM,

    /** 50..79 */
    HIGH,

    /** 80..100 */
    CRITICAL;

    internal companion object {
        fun forScore(score: Int): RiskLevel = when {
            score <= 0 -> SAFE
            score < 25 -> LOW
            score < 50 -> MEDIUM
            score < 80 -> HIGH
            else -> CRITICAL
        }
    }
}
