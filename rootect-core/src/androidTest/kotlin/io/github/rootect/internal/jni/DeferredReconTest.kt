package io.github.rootect

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.rootect.internal.jni.NativeBridge
import java.io.File
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Measurement, not assertion. Records what the app-uid process can actually see, so the
 * deferred signals get decided on evidence instead of on what the shell can reach.
 *
 * Read with: adb logcat -s RootectRecon
 */
@RunWith(AndroidJUnit4::class)
class DeferredReconTest {

    private fun log(section: String, body: StringBuilder.() -> Unit) {
        Log.i("RootectRecon", buildString { appendLine("--- $section"); body() })
    }

    /** Reads a file as the app uid, reporting the failure rather than throwing. */
    private fun read(path: String): String =
        runCatching { File(path).readText().trim() }.getOrElse { "ERR ${it.javaClass.simpleName}" }

    @Test
    fun selinuxVisibility() {
        log("1 SELinux") {
            appendLine("enforce content   : '${read("/sys/fs/selinux/enforce")}'")
            appendLine("enforce probe     : ${NativeBridge.pathProbe("/sys/fs/selinux/enforce")}")
            appendLine("own context       : '${read("/proc/self/attr/current")}'")
            appendLine("policy probe      : ${NativeBridge.pathProbe("/sys/fs/selinux/policy")}")
            appendLine("selinuxfs probe   : ${NativeBridge.pathProbe("/sys/fs/selinux")}")
        }
    }

    @Test
    fun propertySerials() {
        // ro.* is written once at boot. A non-zero counter means something wrote it again,
        // which property_service refuses to do — so only a direct writer like resetprop can.
        val props = listOf(
            "ro.debuggable", "ro.secure", "ro.build.tags", "ro.build.type",
            "ro.build.fingerprint", "ro.boot.verifiedbootstate", "ro.boot.flash.locked",
            "ro.boot.vbmeta.device_state", "ro.boot.veritymode", "ro.boot.warranty_bit",
            "ro.product.model", "ro.product.brand", "ro.crypto.state",
            "sys.boot_completed", "init.svc.adbd",
        ) + (InstrumentationRegistry.getArguments().getString("props")?.split(",") ?: emptyList())

        log("2 property serials") {
            appendLine("%-32s %6s %10s %6s %8s".format("name", "found", "serial", "len", "counter"))
            for (name in props) {
                val (found, serial, len) = NativeBridge.propProbe(name).let {
                    Triple(it[0], it[1], it[2])
                }
                appendLine(
                    "%-32s %6d %10d %6d %8d".format(
                        name, found, serial, len, serial and 0xFFFFFF,
                    ),
                )
            }
        }
    }

    @Test
    fun procOneVisibility() {
        log("3 /proc/1 under hidepid") {
            for (p in listOf("/proc/1", "/proc/1/mountinfo", "/proc/1/maps", "/proc/1/stat")) {
                appendLine("%-20s %d".format(p, NativeBridge.pathProbe(p)))
            }
            // Whether any pid outside our own uid is visible at all.
            val visible = File("/proc").list()?.filter { it.all(Char::isDigit) }?.map(String::toInt)
            appendLine("visible pids      : ${visible?.sorted()?.take(20)}")
            appendLine("visible pid count : ${visible?.size}")
            appendLine("own pid           : ${android.os.Process.myPid()}")
        }
    }

    @Test
    fun listeningSocketVisibility() {
        // Connecting to port 27042 would need INTERNET, which a library cannot require of
        // its host. This is the permission-free alternative, and it sees any port.
        log("5 listening sockets") {
            for (f in listOf("/proc/net/tcp", "/proc/net/tcp6")) {
                appendLine("$f probe ${NativeBridge.pathProbe(f)}")
                val listening = runCatching {
                    File(f).readLines().drop(1)
                        .map { it.trim().split(Regex("\\s+")) }
                        .filter { it.size > 3 && it[3] == "0A" }
                        .map { it[1] }
                }.getOrElse { listOf("ERR ${it.javaClass.simpleName}") }
                appendLine("$f listening: $listening")
            }
        }
    }
}
