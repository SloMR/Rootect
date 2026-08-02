package io.github.rootect.sample

import android.app.Activity
import android.os.Bundle
import android.widget.ScrollView
import android.widget.TextView
import io.github.rootect.Rootect

/**
 * Placeholder dashboard.
 */
class MainActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val view = TextView(this).apply {
            setPadding(48, 96, 48, 48)
            textSize = 16f
            setTextIsSelectable(true)
            text = report()
        }

        setContentView(ScrollView(this).apply { addView(view) })
    }

    private fun report(): CharSequence = buildString {
        appendLine("Rootect — sample")
        appendLine("─".repeat(28))
        appendLine()

        append("native bridge:  ")
        appendLine(runCatching { Rootect.nativePing() }.fold({ it }, { "FAILED — $it" }))

        appendLine()
        appendLine("Detection signals arrive in later phases.")
    }
}
