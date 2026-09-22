package io.github.rootect.internal.detect

import android.content.Context
import android.provider.Settings
import io.github.rootect.signal.Signal
import io.github.rootect.signal.SignalId

internal object SettingsDetector {

    /**
     * Throws when the setting is absent or unreadable. The caller counts that as
     * inconclusive; a default of 0 would report a missing setting as off.
     */
    fun detect(context: Context): List<Signal> {
        val on = Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
        ) != 0
        return if (on) listOf(Signal(SignalId.DEVELOPER_OPTIONS_ENABLED)) else emptyList()
    }
}
