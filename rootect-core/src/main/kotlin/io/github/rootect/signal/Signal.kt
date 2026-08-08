package io.github.rootect.signal

/** One finding. */
public class Signal internal constructor(
    public val id: SignalId,
) {
    public val category: Category get() = id.category
    public val confidence: Confidence get() = id.confidence

    override fun equals(other: Any?): Boolean =
        this === other || (other is Signal && other.id == id)

    override fun hashCode(): Int = id.hashCode()

    override fun toString(): String = "$id($confidence)"
}
