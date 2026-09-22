package io.github.rootect

import android.content.ContentResolver
import android.content.ContextWrapper
import android.os.ParcelFileDescriptor
import android.provider.Settings
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.rootect.internal.detect.SettingsDetector
import io.github.rootect.internal.jni.NativeBridge
import io.github.rootect.internal.jni.NativeProbes
import io.github.rootect.internal.jni.NativeSignals
import io.github.rootect.signal.Category
import io.github.rootect.signal.SignalId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RootDetectionTest {

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun nativeAndKotlinAgreeOnTheSignalBits() {
        // Hand-maintained contract across the JNI boundary; fails the moment one side
        // gains a signal the other does not know about.
        assertEquals(NativeProbes.nativeSignalCount(), NativeSignals.count)
    }

    @Test
    fun decodeMapsEachBitToItsSignal() {
        assertTrue(NativeSignals.decode(0).isEmpty())

        val all = (0 until NativeSignals.count).fold(0) { acc, i -> acc or (1 shl i) }
        assertEquals(NativeSignals.count, NativeSignals.decode(all).size)

        assertEquals(
            listOf(SignalId.MAGISK_ARTIFACT),
            NativeSignals.decode(1 shl 1).map { it.id },
        )
    }

    @Test
    fun scanMapsMatchesArtifactsByBasenameNotPackagePath() {
        // Debug probe over the real basename/token matcher: a package path that merely contains a
        // signal word must not match; a default artifact filename must.
        fun ids(path: String) = NativeSignals.decode(NativeProbes.mapsProbe(path)).map { it.id }

        assertTrue("com.example.friday flagged as Frida",
            ids("/data/app/~~a/com.example.friday-1/base.apk").isEmpty())
        assertTrue("com.example.gadget flagged as Frida",
            ids("/data/app/~~a/com.example.gadget-1/base.apk").isEmpty())
        assertTrue("real Frida agent missed",
            SignalId.FRIDA_LIBRARY_MAPPED in ids("/data/local/tmp/re.frida.server/frida-agent-64.so"))
        assertTrue("gadget library missed",
            SignalId.FRIDA_LIBRARY_MAPPED in ids("/system/lib64/libgadget.so"))
        assertTrue("XposedBridge missed",
            SignalId.XPOSED_FRAMEWORK_PRESENT in ids("/system/framework/XposedBridge.jar"))
    }

    @Test
    fun scanReturnsWellFormedOutput() {
        val scan = NativeBridge.scan(0)
        assertEquals(4, scan.size)

        val valid = (0 until NativeSignals.count).fold(0) { acc, i -> acc or (1 shl i) }
        assertEquals("scan set a bit with no signal behind it", 0, scan[0] and valid.inv())
        assertTrue("inconclusive count must not be negative", scan[1] >= 0)
        assertEquals(
            "scan set a fact bit with nothing behind it",
            0,
            scan[2] and (NativeSignals.FACT_BOOT_STATE_READ or
                NativeSignals.FACT_SIGNING_MATCH or
                NativeSignals.FACT_SIGNING_MISMATCH).inv(),
        )
    }

    @Test
    fun nativeAndKotlinAgreeOnTheResultTag() {
        // If the two mixers drift, every clean device reports DETECTOR_TAMPERED. Several
        // nonces, since a single one could match by luck.
        for (nonce in listOf(0, 1, -1, 0x5F3759DF, Int.MIN_VALUE, Int.MAX_VALUE)) {
            val scan = NativeBridge.scan(nonce)
            assertEquals(
                "tag mismatch for nonce $nonce",
                NativeSignals.tagOf(scan[0], scan[1], scan[2], nonce),
                scan[3],
            )
        }
    }

    @Test
    fun theTagBindsEveryInput() {
        // A bypass returns chosen flags under a nonce it did not pick. The tag is only
        // worth anything if changing any input changes it.
        val n = 999
        assertNotEquals(NativeSignals.tagOf(0, 0, 0, n), NativeSignals.tagOf(1, 0, 0, n))
        assertNotEquals(NativeSignals.tagOf(0, 0, 0, n), NativeSignals.tagOf(0, 1, 0, n))
        assertNotEquals(NativeSignals.tagOf(0, 0, 0, n), NativeSignals.tagOf(0, 0, 1, n))
        assertNotEquals(NativeSignals.tagOf(0, 0, 0, 1), NativeSignals.tagOf(0, 0, 0, 2))
    }

    @Test
    fun analyzeNeverThrowsAndProducesACoherentReport() {
        val report = Rootect.analyze(context)

        assertTrue(report.score in 0..100)
        assertEquals(report.signals.size, report.signals.distinctBy { it.id }.size)
        assertEquals(RiskLevel.forScore(report.score), report.risk)
        assertTrue(report.inconclusiveChecks >= 0)

        // A record of what this device actually saw, not an assertion about it.
        Log.i(
            "RootectScan",
            buildString {
                appendLine("risk=${report.risk} score=${report.score} " +
                    "inconclusive=${report.inconclusiveChecks}")
                appendLine("isRooted=${report.isRooted} rootScore=${report.scoreFor(Category.ROOT)}")
                report.signals.forEach { appendLine("  ${it.id} [${it.confidence}]") }
            },
        )
    }

    // What this device is supposed to be, passed in deliberately rather than guessed:
    //   -Pandroid.testInstrumentationRunnerArguments.rootectExpect=<value>
    //     rooted         rooted phone, root visible
    //     rooted-hidden  rooted phone, root actively hidden from us
    //     clean          unmodified physical device
    //     knox-tripped   unrooted Samsung with its warranty fuse tripped
    //     emulator       clean emulator
    // Unset skips them all, so an accidental CI run cannot assert something untrue.
    private val expectation: String?
        get() = InstrumentationRegistry.getArguments().getString("rootectExpect")

    @Test
    fun rootedDeviceIsDetected() {
        assumeTrue("set rootectExpect=rooted to run this", expectation == "rooted")

        val report = Rootect.analyze(context)
        assertTrue(
            "no root evidence on a device known to be rooted: ${report.signals.map { it.id }}",
            report.signals.any { it.category == Category.ROOT },
        )
        assertTrue("isRooted should be true on a rooted device", report.isRooted)
    }

    @Test
    fun hiddenRootIsNotDetected() {
        assumeTrue("set rootectExpect=rooted-hidden to run this", expectation == "rooted-hidden")

        val report = Rootect.analyze(context)
        assertTrue(
            "MAGISK_ARTIFACT survived DenyList — the gap may be closed; update this test",
            report.signals.none { it.id == SignalId.MAGISK_ARTIFACT },
        )
    }

    @Test
    fun knoxWarrantyBitMatchesTheDeviceProfile() {
        assumeTrue(
            "set rootectExpect=knox-tripped, clean, or emulator to run this",
            expectation == "knox-tripped" || expectation == "clean" || expectation == "emulator",
        )

        val found = Rootect.analyze(context).signals.any {
            it.id == SignalId.KNOX_WARRANTY_BIT_TRIPPED
        }
        if (expectation == "knox-tripped") {
            assertTrue("tripped Knox warranty bit was missed", found)
        } else {
            assertTrue("Knox warranty bit false positive", !found)
        }
    }

    // Developer options state, passed in deliberately rather than guessed, like rootectExpect:
    //   -e rootectDevOptions on|off
    private val devOptionsExpectation: String?
        get() = InstrumentationRegistry.getArguments().getString("rootectDevOptions")

    @Test
    fun developerOptionsSignalMatchesTheDeviceProfile() {
        val expect = devOptionsExpectation
        assumeTrue("set rootectDevOptions=on or off to run this", expect == "on" || expect == "off")

        val found = Rootect.analyze(context).signals.any {
            it.id == SignalId.DEVELOPER_OPTIONS_ENABLED
        }
        if (expect == "on") {
            assertTrue("Developer options are on but DEVELOPER_OPTIONS_ENABLED did not fire", found)
        } else {
            assertTrue("DEVELOPER_OPTIONS_ENABLED false positive with Developer options off", !found)
        }
    }

    @Test
    fun unreadableDeveloperOptionsAreInconclusive() {
        var resolverReads = 0
        val restrictedContext = object : ContextWrapper(context) {
            override fun getContentResolver(): ContentResolver {
                resolverReads++
                throw SecurityException("Settings unavailable")
            }
        }

        // A 0/1 or a never-written setting is a real answer. Only a denied read is inconclusive,
        // so the restricted scan must add a count only when the baseline actually answered.
        val settingsAnswered = runCatching { SettingsDetector.detect(context) }.isSuccess
        val baseline = Rootect.analyze(context)
        val restricted = Rootect.analyze(restrictedContext)

        assertEquals("the settings read must be attempted", 1, resolverReads)
        val extraInconclusive = if (settingsAnswered) 1 else 0
        assertEquals(baseline.inconclusiveChecks + extraInconclusive, restricted.inconclusiveChecks)
        if (!settingsAnswered) {
            assertTrue(
                "a denied developer-options read must be inconclusive",
                baseline.inconclusiveChecks > 0,
            )
        }
        assertTrue(restricted.signals.none { it.id == SignalId.DEVELOPER_OPTIONS_ENABLED })
        assertEquals(baseline.scoreFor(Category.ROOT), restricted.scoreFor(Category.ROOT))
        assertEquals(baseline.isRooted, restricted.isRooted)
    }

    @Test
    fun missingDeveloperOptionsSettingReadsAsOff() {
        assumeTrue(
            "set rootectDevOptions to run this; it deletes and restores the setting",
            devOptionsExpectation != null,
        )
        val key = Settings.Global.DEVELOPMENT_SETTINGS_ENABLED
        val original = shell("settings get global $key")
        try {
            // Android writes the toggle only once it is used, and treats absence as off.
            shell("settings delete global $key")
            assertTrue(SettingsDetector.detect(context).isEmpty())
        } finally {
            if (original == "null") shell("settings delete global $key")
            else shell("settings put global $key $original")
        }
    }

    private fun shell(command: String): String =
        ParcelFileDescriptor.AutoCloseInputStream(
            InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(command),
        ).use { it.readBytes().decodeToString().trim() }

    @Test
    fun uninstrumentedProcessReportsNoHookEvidence() {
        // The control most likely to misfire: a mistake in the CODE_SECTION_MODIFIED
        // comparison shows up here as a CONCLUSIVE signal on an ordinary process.
        val report = Rootect.analyze(context)
        val hooks = report.signalsIn(Category.HOOK)

        assertTrue("false positive: hook evidence with nothing attached: ${hooks.map { it.id }}",
            hooks.isEmpty())
        assertTrue("isHooked must be false when nothing is attached", !report.isHooked)
    }

    @Test
    fun cleanDeviceReportsNoRootEvidence() {
        assumeTrue(
            "set a clean-device rootectExpect profile to run this",
            expectation == "clean" || expectation == "knox-tripped" || expectation == "emulator",
        )

        val report = Rootect.analyze(context)
        val root = report.signalsIn(Category.ROOT)

        // A developer emulator legitimately trips ENVIRONMENT signals, so overall risk may
        // be elevated — but nothing may claim the device is rooted.
        assertTrue("false positive: root evidence on a clean device: ${root.map { it.id }}",
            root.isEmpty())
        assertTrue("isRooted must be false on a clean device", !report.isRooted)
    }
}
