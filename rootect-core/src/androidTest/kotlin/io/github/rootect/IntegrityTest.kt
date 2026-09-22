package io.github.rootect

import android.util.Log
import android.content.ContextWrapper
import android.content.pm.PackageManager
import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.rootect.signal.SignalId
import io.github.rootect.internal.detect.IntegrityDetector
import io.github.rootect.internal.jni.NativeBridge
import io.github.rootect.internal.jni.NativeSignals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
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
    fun nativeSigningDistinguishesMatchMismatchAndUnreadable() {
        val actual = currentSigningSha256()
        assumeTrue("could not read our own signature", actual != null)
        val apk = context.applicationInfo.sourceDir
        val sdk = Build.VERSION.SDK_INT
        val match = NativeBridge.scan(1, apk, actual, sdk)
        assertTrue(match[2] and NativeSignals.FACT_SIGNING_MATCH != 0)

        val wrong = "00".repeat(32)
        assumeTrue("test certificate unexpectedly has the all-zero digest", actual != wrong)
        val mismatch = NativeBridge.scan(2, apk, wrong, sdk)
        assertTrue(mismatch[2] and NativeSignals.FACT_SIGNING_MISMATCH != 0)

        val unreadable = NativeBridge.scan(3, "$apk.missing", actual, sdk)
        assertEquals(0, unreadable[2] and
            (NativeSignals.FACT_SIGNING_MATCH or NativeSignals.FACT_SIGNING_MISMATCH))
    }

    @Test
    fun rotatedApkUsesItsCurrentSignerWhenFixtureIsProvided() {
        // Supply an installed rotated APK and its two cert hashes through instrumentation
        // arguments. No test keys or device-specific APK path belong in the repository.
        val arguments = InstrumentationRegistry.getArguments()
        val apk = arguments.getString("rootectRotationApk")
        val current = arguments.getString("rootectRotationCurrent")
        val previous = arguments.getString("rootectRotationPrevious")
        assumeTrue("requires a rotated APK fixture", apk != null && current != null && previous != null)

        val match = NativeBridge.scan(4, apk!!, current!!, Build.VERSION.SDK_INT)
        assertTrue("the current signer must match", match[2] and NativeSignals.FACT_SIGNING_MATCH != 0)
        assertEquals(NativeSignals.tagOf(match[0], match[1], match[2], 4), match[3])

        val oldSigner = NativeBridge.scan(5, apk, previous!!, Build.VERSION.SDK_INT)
        assertTrue("the pre-rotation signer must not match",
            oldSigner[2] and NativeSignals.FACT_SIGNING_MISMATCH != 0)
    }

    @Test
    fun anUnreadablePackageManagerDoesNotHideANativeMismatch() {
        // Making PackageManager throw must not turn a native mismatch into "unknown".
        val noPackageManager = object : ContextWrapper(context) {
            override fun getPackageManager(): PackageManager = throw SecurityException("hidden")
        }
        val config = RootectConfig(expectedSigningSha256 = "00".repeat(32))

        val hidden = IntegrityDetector.detect(noPackageManager, config, nativeSigning = 1)
        assertTrue(hidden.signals.any { it.id == SignalId.SIGNATURE_MISMATCH })

        val unknown = IntegrityDetector.detect(noPackageManager, config, nativeSigning = null)
        assertFalse(unknown.signals.any { it.id == SignalId.SIGNATURE_MISMATCH })
        assertEquals(1, unknown.inconclusive)
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
            "clean", "knox-tripped", "rooted", "rooted-hidden" ->
                assertFalse("false positive: physical device flagged as an emulator",
                    isEmulatorSignal)
        }
    }

    @Test
    fun anEmptyInstallerAllowlistDisablesTheCheck() {
        // Empty set = check off; a non-empty set excluding the real installer must still fire.
        val disabled = Rootect.analyze(context, RootectConfig(trustedInstallers = emptySet()))
        assertFalse(
            "an empty trustedInstallers set must disable the check, not flag every install",
            disabled.signals.any { it.id == SignalId.UNTRUSTED_INSTALLER },
        )

        val strict = Rootect.analyze(
            context,
            RootectConfig(trustedInstallers = setOf("com.example.no.such.store")),
        )
        assertTrue(
            "a non-empty allowlist excluding the real installer should still flag it",
            strict.signals.any { it.id == SignalId.UNTRUSTED_INSTALLER },
        )
    }

    private fun currentSigningSha256(): String? = try {
        val pm = context.packageManager
        val sigs = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            pm.getPackageInfo(context.packageName,
                android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES).signingInfo?.apkContentsSigners
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(context.packageName,
                android.content.pm.PackageManager.GET_SIGNATURES).signatures
        }
        sigs?.firstOrNull()?.let { cert ->
            java.security.MessageDigest.getInstance("SHA-256")
                .digest(cert.toByteArray())
                .joinToString("") { "%02X".format(it) }
        }
    } catch (_: Throwable) {
        null
    }
}
