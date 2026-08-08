package io.github.rootect

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.rootect.internal.attest.HardwareAttestation
import io.github.rootect.signal.Category
import io.github.rootect.signal.SignalId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AttestationTest {

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private val expectation: String?
        get() = InstrumentationRegistry.getArguments().getString("rootectExpect")

    @Test
    fun hardwareAnswersAndTheExtensionParses() {
        val result = HardwareAttestation.attest()

        // A record of what the hardware actually said, so the numbers below come from
        // observation rather than the spec.
        Log.i(
            "RootectAttest",
            "result=$result softwareOnly=${result?.isSoftwareOnly} " +
                "bootVerified=${result?.isBootVerified}",
        )

        assumeTrue("device produced no attestation", result != null)

        // Values outside these ranges mean the DER walk landed on the wrong field, which is
        // the likeliest way this breaks silently.
        assertTrue("security level out of range: ${result!!.securityLevel}",
            result.securityLevel in 0..2)
        assertTrue("boot state out of range: ${result.verifiedBootState}",
            result.verifiedBootState in 0..3)
    }

    @Test
    fun attestationIsOffUnlessAsked() {
        // It costs hundreds of milliseconds, so it must never run by default.
        val report = Rootect.analyze(context)
        assertTrue(
            "attestation ran without being enabled",
            report.signals.none { it.id.name.startsWith("ATTESTATION_") },
        )
    }

    @Test
    fun enablingAttestationProducesACoherentReport() {
        val report = Rootect.analyze(context, RootectConfig(hardwareAttestation = true))

        assertTrue(report.score in 0..100)
        assertEquals(RiskLevel.forScore(report.score), report.risk)

        Log.i(
            "RootectAttest",
            "risk=${report.risk} score=${report.score} " +
                "env=${report.scoreFor(Category.ENVIRONMENT)} " +
                "signals=${report.signals.map { it.id }}",
        )
    }

    @Test
    fun anUnlockedDeviceIsReportedByHardware() {
        assumeTrue("set rootectExpect=rooted to run this", expectation == "rooted")

        val result = HardwareAttestation.attest()
        assumeTrue("device produced no attestation", result != null)

        // The lab device has an unlocked bootloader. Hardware saying otherwise would mean
        // the parse is reading the wrong field, not that the device relocked itself.
        assertTrue(
            "hardware reported a locked, verified device on a device known to be unlocked",
            !result!!.deviceLocked || !result.isBootVerified,
        )
    }

    @Test
    fun aLockedDeviceIsReportedByHardware() {
        assumeTrue("set rootectExpect=clean to run this", expectation == "clean")

        val result = HardwareAttestation.attest()
        assumeTrue("device produced no attestation", result != null)

        // The mirror of the test above. Together they prove the parse reads a real field
        // rather than returning the same answer whatever the hardware said.
        assertTrue(
            "hardware reported an unlocked or unverified device on a stock device",
            result!!.deviceLocked && result.isBootVerified,
        )
    }

    @Test
    fun contradictionOnlyFiresWhenPropertiesDisagree() {
        val result = HardwareAttestation.attest()
        assumeTrue("device produced no attestation", result != null)

        // Properties already admitting the device is unlocked is not a contradiction.
        val honest = HardwareAttestation.signals(result!!, propertiesSayLocked = false)
        assertFalse(
            "contradiction raised while the properties were honest",
            honest.any { it.id == SignalId.ATTESTATION_CONTRADICTS_PROPERTIES },
        )

        // Properties claiming locked while the hardware says otherwise is the spoof case.
        if (!result.deviceLocked || !result.isBootVerified) {
            val spoofed = HardwareAttestation.signals(result, propertiesSayLocked = true)
            assertTrue(
                "hardware contradicted the properties but nothing was raised",
                spoofed.any { it.id == SignalId.ATTESTATION_CONTRADICTS_PROPERTIES },
            )
        }
    }
}
