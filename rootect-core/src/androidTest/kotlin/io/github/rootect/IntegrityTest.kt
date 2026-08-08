package io.github.rootect

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.rootect.signal.SignalId
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class IntegrityTest {

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private val expectation: String?
        get() = InstrumentationRegistry.getArguments().getString("rootectExpect")

    @Test
    fun signatureCheckIsSkippedWithoutAnExpectedValue() {
        // Rootect cannot know the host app's release key, so an unset expectation must
        // never produce a CONCLUSIVE tamper signal.
        val report = Rootect.analyze(context)
        assertFalse(
            "SIGNATURE_MISMATCH fired with no expected signature configured",
            report.signals.any { it.id == SignalId.SIGNATURE_MISMATCH },
        )
    }

    @Test
    fun aWrongExpectedSignatureIsReportedAsTampering() {
        // Stands in for a resigned APK: if the running signature does not equal what the
        // developer baked in, the APK was repackaged.
        val wrong = "00".repeat(32)
        val report = Rootect.analyze(context, RootectConfig(expectedSigningSha256 = wrong))

        assertTrue(report.signals.any { it.id == SignalId.SIGNATURE_MISMATCH })
        assertTrue("a resigned APK must read as tampered", report.isTampered)
    }

    @Test
    fun theRealSignatureMatchesItself() {
        // Reads our own certificate, feeds it straight back in, and expects agreement.
        // Catches a broken digest or the wrong PackageManager API on any given API level.
        val actual = currentSigningSha256()
        assumeTrue("could not read our own signature", actual != null)

        val report = Rootect.analyze(context, RootectConfig(expectedSigningSha256 = actual))
        assertFalse(
            "the app's own signature was reported as a mismatch",
            report.signals.any { it.id == SignalId.SIGNATURE_MISMATCH },
        )

        // Same value with colons and lower case must behave identically.
        val messy = actual!!.chunked(2).joinToString(":").lowercase()
        val messyReport = Rootect.analyze(context, RootectConfig(expectedSigningSha256 = messy))
        assertFalse(
            "colon-separated lower-case fingerprint was rejected",
            messyReport.signals.any { it.id == SignalId.SIGNATURE_MISMATCH },
        )
    }

    @Test
    fun emulatorIsDetectedOnlyOnAnEmulator() {
        val report = Rootect.analyze(context)
        val isEmulatorSignal = report.signals.any { it.id == SignalId.EMULATOR_FINGERPRINT }

        Log.i("RootectIntegrity", "emulator=$isEmulatorSignal expectation=$expectation")

        // `clean` is a physical device that happens to be unmodified, which is not the same
        // thing as an emulator. Conflating them asserts that real hardware is virtual.
        when (expectation) {
            "emulator" -> assertTrue("emulator not detected on the emulator", isEmulatorSignal)
            "clean", "rooted", "rooted-hidden" ->
                assertFalse("false positive: physical device flagged as an emulator",
                    isEmulatorSignal)
        }
    }

    private fun currentSigningSha256(): String? = try {
        val pm = context.packageManager
        @Suppress("DEPRECATION")
        val sigs = pm.getPackageInfo(
            context.packageName,
            android.content.pm.PackageManager.GET_SIGNATURES,
        ).signatures
        sigs?.firstOrNull()?.let { cert ->
            java.security.MessageDigest.getInstance("SHA-256")
                .digest(cert.toByteArray())
                .joinToString("") { "%02X".format(it) }
        }
    } catch (_: Throwable) {
        null
    }
}
