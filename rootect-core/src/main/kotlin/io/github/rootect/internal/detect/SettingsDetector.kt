package io.github.rootect.internal.detect

import android.content.Context
import android.provider.Settings
import io.github.rootect.signal.Signal
import io.github.rootect.signal.SignalId

internal object SettingsDetector {

    /**
     * A never-written setting reads as off, as Android's own reader treats it. A denied or
     * failed read throws, and the caller counts that as inconclusive.
     */
    fun detect(context: Context): List<Signal> {
        val on = try {
            Settings.Global.getInt(
                context.contentResolver,
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
            ) != 0
        } catch (_: Settings.SettingNotFoundException) {
            false
        }
        val adbOn = Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.ADB_ENABLED,
            0,
        ) != 0
        return buildList {
            if (on) add(Signal(SignalId.DEVELOPER_OPTIONS_ENABLED))
            if (adbOn) add(Signal(SignalId.ADB_ENABLED))
        }
    }
}
