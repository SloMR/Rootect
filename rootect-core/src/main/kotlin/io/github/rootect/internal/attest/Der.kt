package io.github.rootect.internal.attest

// Minimal DER reader, enough to walk a key attestation extension. Hand-rolled because
// rootect-core ships no dependencies.
internal class Der(private val bytes: ByteArray, private var pos: Int = 0, private val end: Int = bytes.size) {

    /** True while unread bytes remain. */
    fun hasNext(): Boolean = pos < end

    /** Reads the next element's tag, leaving the position on its length. */
    private fun readTag(): Long {
        var tag = (bytes[pos++].toInt() and 0xFF).toLong()
        if (tag and 0x1F == 0x1FL) { // high tag number: continue in base-128
            var value = 0L
            while (true) {
                val b = bytes[pos++].toInt() and 0xFF
                value = (value shl 7) or (b and 0x7F).toLong()
                if (b and 0x80 == 0) break
            }
            tag = value
        } else {
            tag = tag and 0x1F
        }
        return tag
    }

    /** Reads a definite-form length, short or long. */
    private fun readLength(): Int {
        val first = bytes[pos++].toInt() and 0xFF
        if (first and 0x80 == 0) return first
        var length = 0
        repeat(first and 0x7F) { length = (length shl 8) or (bytes[pos++].toInt() and 0xFF) }
        return length
    }

    /** One element: its tag, and a reader over its contents. */
    class Element(val tag: Long, val contentStart: Int, val contentEnd: Int, private val src: ByteArray) {
        /** Reader over this element's contents. */
        fun reader(): Der = Der(src, contentStart, contentEnd)

        /** Contents interpreted as an unsigned integer or enumerated value. */
        fun asInt(): Int {
            var value = 0
            for (i in contentStart until contentEnd) value = (value shl 8) or (src[i].toInt() and 0xFF)
            return value
        }

        /** Contents interpreted as a DER boolean. */
        fun asBoolean(): Boolean =
            contentEnd > contentStart && src[contentStart].toInt() != 0

        /** Raw contents. */
        fun bytes(): ByteArray = src.copyOfRange(contentStart, contentEnd)
    }

    /** Advances past the next element and returns it, or null at the end. */
    fun next(): Element? {
        if (!hasNext()) return null
        val tag = readTag()
        val length = readLength()
        val start = pos
        pos += length
        return Element(tag, start, minOf(start + length, end), bytes)
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
}
