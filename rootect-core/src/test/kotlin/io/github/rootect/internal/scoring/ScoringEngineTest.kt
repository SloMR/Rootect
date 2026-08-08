package io.github.rootect

import io.github.rootect.internal.scoring.ScoringEngine
import io.github.rootect.signal.Category
import io.github.rootect.signal.Signal
import io.github.rootect.signal.SignalId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ScoringEngineTest {

    private fun signals(vararg ids: SignalId) = ids.map { Signal(it) }

    @Test
    fun `no signals scores zero`() {
        assertEquals(0, ScoringEngine.score(emptyList()))
    }

    @Test
    fun `a single conclusive signal pins the score at 100`() {
        assertEquals(100, ScoringEngine.score(signals(SignalId.KERNEL_ROOT_SYSCALL)))
    }

    @Test
    fun `weights combine with diminishing returns rather than adding`() {
        assertEquals(
            19,
            ScoringEngine.score(signals(SignalId.TEST_KEYS_BUILD, SignalId.UNTRUSTED_INSTALLER)),
        )
    }

    @Test
    fun `a pile of minor findings does not reach critical`() {
        val score = ScoringEngine.score(
            signals(
                SignalId.TEST_KEYS_BUILD,
                SignalId.UNTRUSTED_INSTALLER,
                SignalId.ROOT_MANAGER_PACKAGE,
                SignalId.DEBUGGER_ATTACHED,
                SignalId.DEBUGGABLE_BUILD,
            ),
        )
        assertEquals(66, score)
        assertEquals(RiskLevel.HIGH, RiskLevel.forScore(score))
    }

    @Test
    fun `the same id found twice counts once`() {
        // Two probes can find the same thing in different places; that is one finding.
        val once = ScoringEngine.score(listOf(Signal(SignalId.SU_BINARY)))
        val twice = ScoringEngine.score(
            listOf(
                Signal(SignalId.SU_BINARY),
                Signal(SignalId.SU_BINARY),
            ),
        )
        assertEquals(once, twice)
    }

    @Test
    fun `adding evidence never lowers the score`() {
        var previous = 0
        val accumulated = mutableListOf<Signal>()
        for (id in SignalId.entries) {
            accumulated += Signal(id)
            val score = ScoringEngine.score(accumulated)
            assertTrue("score dropped after adding $id", score >= previous)
            previous = score
        }
    }

    @Test
    fun `category scores ignore other categories`() {
        val mixed = signals(SignalId.SU_BINARY, SignalId.FRIDA_THREAD_PRESENT)
        assertEquals(50, ScoringEngine.scoreFor(mixed, Category.ROOT))
        assertEquals(50, ScoringEngine.scoreFor(mixed, Category.HOOK))
        assertEquals(0, ScoringEngine.scoreFor(mixed, Category.TAMPER))
    }
}
