package io.github.rootect.internal.attest

import io.github.rootect.signal.SignalId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HardwareAttestationTest {

    @Test
    fun `software-only record remains usable without root of trust`() {
        val result = HardwareAttestation.parseExtension(keyDescription(0, 0, withRoot = false))

        assertTrue(result!!.isSoftwareOnly)
        assertNull(result.deviceLocked)
        assertNull(result.verifiedBootState)
        assertEquals(
            listOf(SignalId.ATTESTATION_SOFTWARE_ONLY),
            HardwareAttestation.signals(result, propertiesSayLocked = true).map { it.id },
        )
    }

    @Test
    fun `mixed hardware levels use the weaker level`() {
        val result = HardwareAttestation.parseExtension(keyDescription(2, 1, withRoot = true))

        assertEquals(1, result!!.securityLevel)
        assertEquals(true, result.deviceLocked)
        assertTrue(result.isBootVerified)
    }

    @Test
    fun `unknown security level is rejected`() {
        assertNull(HardwareAttestation.parseExtension(keyDescription(3, 3, withRoot = true)))
    }

    @Test
    fun `a hardware record with no root of trust is rejected`() {
        // The removed fail-open: a hardware-level key with no rootOfTrust must not be read
        // as a locked, verified device.
        assertNull(HardwareAttestation.parseExtension(keyDescription(1, 1, withRoot = false)))
    }

    @Test
    fun `an out-of-range boot state is rejected`() {
        assertNull(
            HardwareAttestation.parseExtension(keyDescription(1, 1, withRoot = true, bootState = 7)),
        )
    }

    private fun keyDescription(
        attestationLevel: Int,
        keyMintLevel: Int,
        withRoot: Boolean,
        bootState: Int = 0,
    ): ByteArray {
        val root = if (withRoot) {
            context(
                704,
                sequence(
                    element(0x04, byteArrayOf(1)),
                    element(0x01, byteArrayOf(0xFF.toByte())),
                    integer(bootState, 0x0A),
                ),
            )
        } else {
            byteArrayOf()
        }
        val description = sequence(
            integer(4),
            integer(attestationLevel, 0x0A),
            integer(4),
            integer(keyMintLevel, 0x0A),
            element(0x04, ByteArray(32) { it.toByte() }),
            element(0x04, byteArrayOf()),
            sequence(),
            sequence(root),
        )
        return element(0x04, description)
    }

    private fun integer(value: Int, tag: Int = 0x02): ByteArray =
        element(tag, byteArrayOf(value.toByte()))

    private fun sequence(vararg values: ByteArray): ByteArray =
        element(0x30, values.fold(byteArrayOf()) { all, value -> all + value })

    private fun context(number: Int, value: ByteArray): ByteArray {
        val encoded = mutableListOf(number and 0x7F)
        var remaining = number ushr 7
        while (remaining != 0) {
            encoded += 0x80 or (remaining and 0x7F)
            remaining = remaining ushr 7
        }
        return element(byteArrayOf(0xBF.toByte()) + encoded.reversed().map(Int::toByte), value)
    }

    private fun element(tag: Int, value: ByteArray): ByteArray =
        element(byteArrayOf(tag.toByte()), value)

    private fun element(tag: ByteArray, value: ByteArray): ByteArray {
        val length = if (value.size < 128) {
            byteArrayOf(value.size.toByte())
        } else {
            byteArrayOf(0x81.toByte(), value.size.toByte())
        }
        return tag + length + value
    }
}
