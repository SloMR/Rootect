package io.github.rootect

import kotlin.math.roundToInt

/** Combines signal confidences into a 0..100 score. */
internal object ScoringEngine {

    /** Combined score for every signal given. */
    fun score(signals: Collection<Signal>): Int {
        if (signals.isEmpty()) return 0

        // Noisy-OR, not a sum: multiply the odds every signal is a false alarm, invert.
        // Duplicate ids count once.
        var complement = 1.0
        for (id in signals.mapTo(LinkedHashSet()) { it.id }) {
            complement *= 1.0 - (id.confidence.weight / 100.0)
        }
        return ((1.0 - complement) * 100).roundToInt().coerceIn(0, 100)
    }

    /** Combined score for one category only. */
    fun scoreFor(signals: Collection<Signal>, category: Category): Int =
        score(signals.filter { it.category == category })
}
