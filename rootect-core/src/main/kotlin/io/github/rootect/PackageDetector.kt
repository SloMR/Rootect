package io.github.rootect

import android.content.Context
import android.content.pm.PackageManager

internal object PackageDetector {

    private val MANAGERS = listOf(
        "com.topjohnwu.magisk",
        "io.github.huskydg.magisk",
        "io.github.vvb2060.magisk",
        "me.weishu.kernelsu",
        "me.bmax.apatch",
        "eu.chainfire.supersu",
        "com.noshufou.android.su",
        "com.koushikdutta.superuser",
    )

    fun detect(context: Context): List<Signal> {
        val pm = context.packageManager
        val found = MANAGERS.filter { pkg ->
            try {
                pm.getPackageInfo(pkg, 0)
                true
            } catch (_: PackageManager.NameNotFoundException) {
                false
            } catch (_: Exception) {
                false
            }
        }
        return if (found.isEmpty()) emptyList() else listOf(Signal(SignalId.ROOT_MANAGER_PACKAGE))
    }
}
