package io.github.rootect

import io.github.rootect.internal.scoring.ScoringEngine
import io.github.rootect.signal.Category
import io.github.rootect.signal.Signal

/** What an analysis found. */
public class RootectReport internal constructor(
    public val signals: List<Signal>,
    /** Checks that could not complete. Not evidence, but "found nothing" is weaker if set. */
    public val inconclusiveChecks: Int = 0,
    /** Which checks could not finish. A check can fail more than once, so this is a set. */
    public val inconclusiveSources: Set<InconclusiveCheck> = emptySet(),
) {
    /** 0..100 across every category. */
    public val score: Int = ScoringEngine.score(signals)
    public val risk: RiskLevel = RiskLevel.forScore(score)

    /** Same maths as [score], one category only. */
    public fun scoreFor(category: Category): Int = ScoringEngine.scoreFor(signals, category)

    /** Evidence from one category. */
    public fun signalsIn(category: Category): List<Signal> =
        signals.filter { it.category == category }

    // Each rollup looks at its own category only.
    public val isRooted: Boolean get() = scoreFor(Category.ROOT) >= ROLLUP_THRESHOLD
    public val isHooked: Boolean get() = scoreFor(Category.HOOK) >= ROLLUP_THRESHOLD
    public val isTampered: Boolean get() = scoreFor(Category.TAMPER) >= ROLLUP_THRESHOLD
    public val isEmulator: Boolean get() = scoreFor(Category.EMULATOR) >= ROLLUP_THRESHOLD
    public val isDebugged: Boolean get() = scoreFor(Category.DEBUG) >= ROLLUP_THRESHOLD

    override fun toString(): String =
        "RootectReport(risk=$risk, score=$score, signals=${signals.size}, " +
            "inconclusive=$inconclusiveChecks)"

    internal companion object {
        /** One STRONG signal, or three MODERATE ones. */
        const val ROLLUP_THRESHOLD: Int = 50

        val EMPTY: RootectReport = RootectReport(emptyList())
    }
}
