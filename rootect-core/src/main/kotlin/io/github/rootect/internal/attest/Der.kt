package io.github.rootect.internal.attest

// Minimal DER reader, enough to walk a key attestation extension. Hand-rolled because
// rootect-core ships no dependencies.
internal class Der(
    private val bytes: ByteArray,
    private var pos: Int = 0,
    private val end: Int = bytes.size,
) {

    /** True while unread bytes remain. */
    fun hasNext(): Boolean = pos < end

    /** Next element's tag, or -1 if malformed. Leaves the position on its length. */
    private fun readTag(): Long {
        if (pos >= end) return -1L

        val first = bytes[pos++].toInt() and 0xFF
        if (first and 0x1F != 0x1F) return (first and 0x1F).toLong()

        // High tag number: base-128, continuing while the top bit is set.
        var value = 0L
        repeat(MAX_TAG_BYTES) {
            if (pos >= end) return -1L
            val b = bytes[pos++].toInt() and 0xFF
            value = (value shl 7) or (b and 0x7F).toLong()
            if (b and 0x80 == 0) return value
        }
        return -1L
    }

    /** Definite-form length, or -1 if malformed, indefinite, or past the buffer. */
    private fun readLength(): Int {
        if (pos >= end) return -1

        val first = bytes[pos++].toInt() and 0xFF
        if (first and 0x80 == 0) return first

        // 0 is the indefinite form, forbidden in DER. Over four bytes cannot fit an Int.
        val count = first and 0x7F
        if (count == 0 || count > 4) return -1

        var length = 0
        repeat(count) {
            if (pos >= end) return -1
            length = (length shl 8) or (bytes[pos++].toInt() and 0xFF)
        }
        return if (length < 0) -1 else length
    }

    /** One element: its tag, and a reader over its contents. */
    class Element(
        val tag: Long,
        private val contentStart: Int,
        private val contentEnd: Int,
        private val src: ByteArray,
    ) {
        /** Reader over this element's contents. */
        fun reader(): Der = Der(src, contentStart, contentEnd)

        /** Contents interpreted as an unsigned integer or enumerated value. */
        fun asInt(): Int {
            var value = 0
            for (i in contentStart until contentEnd) {
                value = (value shl 8) or (src[i].toInt() and 0xFF)
            }
            return value
        }

        /** Contents interpreted as a DER boolean. */
        fun asBoolean(): Boolean = contentEnd > contentStart && src[contentStart].toInt() != 0

        /** Raw contents. */
        fun bytes(): ByteArray = src.copyOfRange(contentStart, contentEnd)
    }

    /** Advances past the next element and returns it, or null at the end or on bad input. */
    fun next(): Element? {
        if (!hasNext()) return null

        val tag = readTag()
        val length = if (tag < 0) -1 else readLength()

        // Malformed ends the walk rather than resyncing through attacker-chosen bytes.
        if (tag < 0 || length < 0 || length > end - pos) {
            pos = end
            return null
        }

        val start = pos
        pos = start + length
        return Element(tag, start, pos, bytes)
    }

    /** Reads every remaining element. */
    fun all(): List<Element> = buildList {
        while (true) add(next() ?: break)
    }

    /** First element carrying `tag`, or null. */
    fun find(tag: Long): Element? {
        while (true) {
            val e = next() ?: return null
            if (e.tag == tag) return e
        }
    }

    private companion object {
        const val MAX_TAG_BYTES = 4
    }
}
