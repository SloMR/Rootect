package io.github.rootect

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.rootect.internal.jni.NativeProbes
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Proves the native foundation works on a real device, including the hostile cases. */
@RunWith(AndroidJUnit4::class)
class NativeBridgeTest {

    private val dir: File
        get() = InstrumentationRegistry.getInstrumentation().targetContext.cacheDir

    private fun fixture(name: String, content: String): String =
        File(dir, name).apply { writeText(content) }.absolutePath

    // error, truncated, lines
    private fun probe(path: String) = NativeProbes.parserProbe(path)

    @Test
    fun foundationSelfTestPasses() {
        assertTrue(NativeProbes.selfTest())
    }

    @Test
    fun readsEveryLine() {
        val r = probe(fixture("three.txt", "a\nbb\nccc\n"))
        assertEquals(0, r[0])
        assertEquals(0, r[1])
        assertEquals(3, r[2])
    }

    @Test
    fun readsAFinalLineWithNoTrailingNewline() {
        val r = probe(fixture("no-eol.txt", "a\nb"))
        assertEquals(0, r[0])
        assertEquals(2, r[2])
    }

    @Test
    fun handlesAnEmptyFile() {
        val r = probe(fixture("empty.txt", ""))
        assertEquals(0, r[0])
        assertEquals(0, r[2])
    }

    @Test
    fun handlesBlankLines() {
        val r = probe(fixture("blank.txt", "\n\n\n"))
        assertEquals(0, r[0])
        assertEquals(3, r[2])
    }

    @Test
    fun readsALineExactlyAtTheBufferLimit() {
        // 4095 chars is the largest line that still fits alongside its NUL.
        val r = probe(fixture("edge.txt", "x".repeat(4095) + "\n"))
        assertEquals(0, r[0])
        assertEquals(0, r[1])
        assertEquals(1, r[2])
    }

    @Test
    fun reportsAnOverLongLineInsteadOfDroppingIt() {
        // Padding a line past the buffer is how an attacker hides one, so it must surface
        // as "could not check" rather than silently reading as absent.
        val r = probe(fixture("long.txt", "y".repeat(9000) + "\n" + "ok\n"))
        assertEquals(0, r[0])
        assertEquals(1, r[1])
        assertEquals(1, r[2])
    }

    @Test
    fun reportsAnOverLongFinalLineWithNoNewline() {
        val r = probe(fixture("long-eof.txt", "z".repeat(9000)))
        assertEquals(1, r[1])
        assertEquals(0, r[2])
    }

    @Test
    fun missingFileReportsEnoent() {
        val r = probe(File(dir, "definitely-not-here").absolutePath)
        assertEquals(-2, r[0]) // -ENOENT
    }

    @Test
    fun aDirectoryIsDistinguishableFromAMissingFile() {
        // Opening a directory succeeds; reading it fails with EISDIR. The point is that the
        // reason survives instead of collapsing into a bare false.
        val r = probe(dir.absolutePath)
        assertEquals(-21, r[0]) // -EISDIR
    }

    @Test
    fun pathProbeSeparatesAbsentFromPresent() {
        assertEquals(0, NativeProbes.pathProbe(dir.absolutePath))
        assertEquals(-2, NativeProbes.pathProbe(File(dir, "nope").absolutePath))
    }
}
