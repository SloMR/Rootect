package io.github.rootect

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
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
        assertEquals(NativeBridge.nativeSignalCount(), NativeSignals.count)
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
    fun scanReturnsWellFormedOutput() {
        val scan = NativeBridge.scan()
        assertEquals(2, scan.size)

        val valid = (0 until NativeSignals.count).fold(0) { acc, i -> acc or (1 shl i) }
        assertEquals("scan set a bit with no signal behind it", 0, scan[0] and valid.inv())
        assertTrue("inconclusive count must not be negative", scan[1] >= 0)
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
    //   -Pandroid.testInstrumentationRunnerArguments.rootectExpect=rooted   (Real Device)
    //   -Pandroid.testInstrumentationRunnerArguments.rootectExpect=clean    (emulator)
    // Unset skips both, so an accidental CI run cannot assert something untrue.
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
        assumeTrue("set rootectExpect=clean to run this", expectation == "clean")

        val report = Rootect.analyze(context)
        val root = report.signalsIn(Category.ROOT)

        // A developer emulator legitimately trips ENVIRONMENT signals, so overall risk may
        // be elevated — but nothing may claim the device is rooted.
        assertTrue("false positive: root evidence on a clean device: ${root.map { it.id }}",
            root.isEmpty())
        assertTrue("isRooted must be false on a clean device", !report.isRooted)
    }
}
