package io.github.rootect

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.rootect.internal.attest.HardwareAttestation
import java.io.File
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ChainExportTest {

    private val dir get() = InstrumentationRegistry.getInstrumentation().targetContext.cacheDir

    @Test
    fun theChainCanBeExportedForServerVerification() {
        val challenge = ByteArray(32) { it.toByte() }
        val chain = RootectAttestation.chain(challenge)
        assumeTrue("device produced no attestation", chain != null)

        assertTrue("a chain should have more than just the leaf", chain!!.size >= 2)

        // Written where the harness can pull them for server-verifier regression tests.
        chain.forEachIndexed { i, der ->
            File(dir, "attest-$i.der").writeBytes(der)
        }
        Log.i(
            "RootectChain",
            "certs=${chain.size} challenge=${challenge.joinToString("") { "%02x".format(it) }} " +
                "dir=${dir.absolutePath}",
        )
    }

    @Test
    fun aReplayedChallengeIsRejected() {
        val issued = ByteArray(32) { 0x5A }
        val chain = HardwareAttestation.chainFor(issued)
        assumeTrue(chain != null)
        val parsed = HardwareAttestation.parseChain(chain!!, issued)
        assumeTrue("device chain does not meet policy", parsed != null)

        assertNull(
            "accepted a chain for another challenge",
            HardwareAttestation.parseChain(chain, ByteArray(32) { 0x33 }),
        )
    }

    @Test
    fun nullChallengeChainIsHandled() {
        assertNull(RootectAttestation.chain(ByteArray(0)))
    }
}
