package io.github.rootect

/** One finding. */
public class Signal internal constructor(
    public val id: SignalId,
    public val detail: String? = null,
) {
    public val category: Category get() = id.category
    public val confidence: Confidence get() = id.confidence

    override fun equals(other: Any?): Boolean =
        this === other || (other is Signal && other.id == id && other.detail == detail)

    override fun hashCode(): Int = 31 * id.hashCode() + (detail?.hashCode() ?: 0)

    override fun toString(): String =
        if (detail == null) "$id($confidence)" else "$id($confidence): $detail"
}
