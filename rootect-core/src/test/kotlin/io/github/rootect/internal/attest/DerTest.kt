package io.github.rootect.internal.attest

import java.util.Random
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The chain comes from a device the attacker may own, so every malformed shape is reachable. */
class DerTest {

    private fun der(vararg bytes: Int) = Der(ByteArray(bytes.size) { bytes[it].toByte() })

    @Test
    fun `reads a nested sequence`() {
        // SEQUENCE { INTEGER 5, BOOLEAN true }
        val seq = der(0x30, 0x06, 0x02, 0x01, 0x05, 0x01, 0x01, 0xFF).next()

        assertNotNull(seq)
        assertEquals(16L, seq!!.tag)

        val fields = seq.reader().all()
        assertEquals(2, fields.size)
        assertEquals(5, fields[0].asInt())
        assertTrue(fields[1].asBoolean())
    }

    @Test
    fun `reads the high tag number the attestation extension uses`() {
        // rootOfTrust is [704], so the base-128 path is on the real parsing route.
        val e = der(0xBF, 0x85, 0x40, 0x01, 0x00).next()

        assertNotNull(e)
        assertEquals(704L, e!!.tag)
    }

    @Test
    fun `an element claiming more content than exists yields null`() {
        assertNull(der(0x30, 0x08, 0x01, 0x02).next())
    }

    @Test
    fun `a header cut short yields null`() {
        assertNull(der(0x30).next())
        assertNull(Der(ByteArray(0)).next())
    }

    @Test
    fun `the indefinite length form is rejected`() {
        // Valid BER, forbidden in DER; would otherwise read as a zero-length element.
        assertNull(der(0x30, 0x80, 0x00, 0x00).next())
    }

    @Test
    fun `a length too wide for an Int is rejected`() {
        assertNull(der(0x30, 0x85, 0x01, 0x01, 0x01, 0x01, 0x01).next())
    }

    @Test
    fun `a length that would read back negative is rejected`() {
        // Four 0xFF bytes land on -1, which slips past a `length > remaining` check.
        assertNull(der(0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF).next())
    }

    @Test
    fun `an unterminated high tag number yields null`() {
        assertNull(der(0xBF, 0x80, 0x80, 0x80, 0x80, 0x80).next())
    }

    @Test
    fun `a malformed element ends the walk instead of resyncing`() {
        val d = der(0x02, 0x01, 0x07, 0x30, 0x40, 0x00)

        assertEquals(7, d.next()!!.asInt())
        assertNull(d.next())
        assertNull(d.next())
    }

    @Test
    fun `arbitrary bytes never throw`() {
        val random = Random(20260809)

        repeat(20_000) {
            val bytes = ByteArray(random.nextInt(64)).also(random::nextBytes)
            val reader = Der(bytes)

            while (true) {
                val e = reader.next() ?: break
                e.asInt()
                e.asBoolean()
                e.bytes()
                e.reader().all().forEach { nested ->
                    nested.asInt()
                    nested.asBoolean()
                    nested.bytes()
                }
            }
        }
    }
}
