package io.github.rootect

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RootectReportTest {

    private fun report(vararg ids: SignalId) = RootectReport(ids.map { Signal(it) })

    @Test
    fun `an empty report is safe`() {
        val report = RootectReport.EMPTY
        assertEquals(0, report.score)
        assertEquals(RiskLevel.SAFE, report.risk)
        assertFalse(report.isRooted)
    }

    @Test
    fun `risk bands sit where the docs claim`() {
        assertEquals(RiskLevel.SAFE, RiskLevel.forScore(0))
        assertEquals(RiskLevel.LOW, RiskLevel.forScore(1))
        assertEquals(RiskLevel.LOW, RiskLevel.forScore(24))
        assertEquals(RiskLevel.MEDIUM, RiskLevel.forScore(25))
        assertEquals(RiskLevel.MEDIUM, RiskLevel.forScore(49))
        assertEquals(RiskLevel.HIGH, RiskLevel.forScore(50))
        assertEquals(RiskLevel.HIGH, RiskLevel.forScore(79))
        assertEquals(RiskLevel.CRITICAL, RiskLevel.forScore(80))
        assertEquals(RiskLevel.CRITICAL, RiskLevel.forScore(100))
    }

    @Test
    fun `an unrooted custom rom is not reported as rooted`() {
        // LineageOS, unlocked bootloader, test-keys build, no root at all.
        val report = report(SignalId.BOOTLOADER_UNLOCKED, SignalId.TEST_KEYS_BUILD)

        assertEquals(RiskLevel.HIGH, report.risk)
        assertFalse(report.isRooted)
        assertEquals(0, report.scoreFor(Category.ROOT))
    }

    @Test
    fun `one conclusive root signal is enough to report rooted`() {
        val report = report(SignalId.MOUNT_NAMESPACE_DIVERGENCE)
        assertTrue(report.isRooted)
        assertEquals(RiskLevel.CRITICAL, report.risk)
    }

    @Test
    fun `rollups are independent per category`() {
        val report = report(SignalId.CODE_SECTION_MODIFIED)
        assertTrue(report.isHooked)
        assertFalse(report.isRooted)
        assertFalse(report.isTampered)
    }

    @Test
    fun `signals can be filtered by category`() {
        val report = report(SignalId.SU_BINARY, SignalId.FRIDA_THREAD_PRESENT)
        assertEquals(1, report.signalsIn(Category.ROOT).size)
        assertEquals(SignalId.SU_BINARY, report.signalsIn(Category.ROOT).single().id)
    }
}
