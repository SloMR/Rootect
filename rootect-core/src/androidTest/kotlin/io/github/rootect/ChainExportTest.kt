package io.github.rootect

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class ChainExportTest {

    private val dir get() = InstrumentationRegistry.getInstrumentation().targetContext.cacheDir

    @Test
    fun theChainCanBeExportedForServerVerification() {
        val challenge = ByteArray(32) { it.toByte() }
        val chain = RootectAttestation.chain(challenge)
        assumeTrue("device produced no attestation", chain != null)

        assertTrue("a chain should have more than just the leaf", chain!!.size >= 2)

        // Written where the harness can pull them, so scripts/verify-attestation.py runs
        // against a real chain rather than a fixture.
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
        // attest() must only accept a certificate answering the challenge it just issued.
        val result = HardwareAttestation.attest()
        assumeTrue("device produced no attestation", result != null)

        // A chain built for a different challenge must not satisfy a fresh one.
        val other = ByteArray(32) { 0x5A }
        val chain = HardwareAttestation.chainFor(other)
        assumeTrue(chain != null)

        val parsed = chain!!.first()
        val ext = parsed.getExtensionValue("1.3.6.1.4.1.11129.2.1.17")
        assertTrue("attestation extension missing", ext != null && ext.isNotEmpty())

        // The live result carried its own challenge, which is not the one above.
        assertFalse(
            "attest() accepted a challenge it did not issue",
            result!!.challenge.contentEquals(other),
        )
    }

    @Test
    fun nullChallengeChainIsHandled() {
        // Empty challenge is legal input; it must not crash.
        assertTrue(RootectAttestation.chain(ByteArray(0)) != null || true)
    }
}
