package io.github.rootect.sample

import android.app.Activity
import android.os.Bundle
import android.widget.ScrollView
import android.widget.TextView
import io.github.rootect.Rootect
import io.github.rootect.RootectConfig

// SHA-256 of the certificate this app should be signed with. A real app pastes its release
// certificate here; anything else means the APK was resigned, therefore repackaged.
// Null skips the check, which is what lets this sample build on any machine.
private val EXPECTED_SIGNING_SHA256: String? = null

/** Placeholder dashboard. */
class MainActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val view = TextView(this).apply {
            setPadding(48, 96, 48, 48)
            textSize = 16f
            text = report()
            // Tap anywhere to re-scan, so conditions can be changed on a running app and
            // the effect seen without a restart.
            minHeight = resources.displayMetrics.heightPixels
            setOnClickListener { text = report() }
        }

        setContentView(ScrollView(this).apply { addView(view) })
    }

    /** Runs a scan and renders it. */
    private fun report(): CharSequence = buildString {
        val report = Rootect.analyze(
            this@MainActivity,
            RootectConfig(expectedSigningSha256 = EXPECTED_SIGNING_SHA256),
        )

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
