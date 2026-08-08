package io.github.rootect.internal.detect

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import io.github.rootect.RootectConfig
import io.github.rootect.signal.Signal
import io.github.rootect.signal.SignalId
import java.security.MessageDigest

// Checks about the app itself rather than the device it runs on.
internal object IntegrityDetector {

    /** Emits signature, debuggable and installer signals. */
    fun detect(context: Context, config: RootectConfig): List<Signal> {
        val signals = mutableListOf<Signal>()

        if (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) {
            signals += Signal(SignalId.DEBUGGABLE_BUILD)
        }

        if (installerOf(context) !in config.trustedInstallers) {
            signals += Signal(SignalId.UNTRUSTED_INSTALLER)
        }

        // Only checkable when the host app tells us what to expect. A mismatch means the
        // APK was resigned, which means it was repackaged. Failing to read our own
        // signature counts as a mismatch: it should never happen on an intact install.
        val expected = config.expectedSigningSha256?.let(::normalise)
        if (expected != null && signingSha256(context) != expected) {
            signals += Signal(SignalId.SIGNATURE_MISMATCH)
        }

        return signals
    }

    /** Package that installed us, or null for a sideload. */
    private fun installerOf(context: Context): String? = try {
        val pm = context.packageManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(context.packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(context.packageName)
        }
    } catch (_: Throwable) {
        null
    }

    /** SHA-256 of our signing certificate, or null if it cannot be read. */
    private fun signingSha256(context: Context): String? = try {
        val pm = context.packageManager
        val certs: Array<out android.content.pm.Signature>? =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                // apkContentsSigners is who signed *this* APK, which is the question here.
                // signingCertificateHistory would also return pre-rotation keys.
                pm.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES,
                ).signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES).signatures
            }

        certs?.firstOrNull()?.let { cert ->
            MessageDigest.getInstance("SHA-256")
                .digest(cert.toByteArray())
                .joinToString("") { "%02X".format(it) }
        }
    } catch (_: Throwable) {
        null
    }

    /** Strips colons and upper-cases, so callers can paste either common format. */
    private fun normalise(fingerprint: String): String =
        fingerprint.replace(":", "").replace(" ", "").uppercase()
}
