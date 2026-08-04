package io.github.rootect.sample

import android.app.Activity
import android.os.Bundle
import android.widget.ScrollView
import android.widget.TextView
import io.github.rootect.Rootect

/** Placeholder dashboard. */
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
        val report = Rootect.analyze(this@MainActivity)

        appendLine("Rootect — sample")
        appendLine("─".repeat(28))
        appendLine()
        appendLine("risk:     ${report.risk}")
        appendLine("score:    ${report.score}")
        appendLine("rooted:   ${report.isRooted}")
        appendLine()

        if (report.signals.isEmpty()) {
            appendLine("No signals.")
        } else {
            report.signals.forEach { appendLine("• ${it.id}  [${it.confidence}]") }
        }

        if (report.inconclusiveChecks > 0) {
            appendLine()
            appendLine("${report.inconclusiveChecks} check(s) could not complete.")
        }
    }
}
