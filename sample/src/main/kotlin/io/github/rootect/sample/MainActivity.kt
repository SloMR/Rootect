package io.github.rootect.sample

import android.app.Activity
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import io.github.rootect.Category
import io.github.rootect.Confidence
import io.github.rootect.RiskLevel
import io.github.rootect.Rootect
import io.github.rootect.RootectConfig
import io.github.rootect.RootectReport
import io.github.rootect.Signal

// SHA-256 of the certificate this app should be signed with. A real app pastes its release
// certificate here; anything else means the APK was resigned, therefore repackaged.
// Null skips the check, which is what lets this sample build on any machine.
private val EXPECTED_SIGNING_SHA256: String? = null

/**
 * Live dashboard for a Rootect scan.
 *
 * Plain views and no dependencies, so it also shows that integrating the library costs a
 * host app nothing beyond the single call in [scan].
 */
class MainActivity : Activity() {

    private lateinit var container: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(BACKGROUND)
        }
        setContentView(ScrollView(this).apply { addView(container) })
        render()
    }

    /** The whole integration: one call, optionally configured. */
    private fun scan(): RootectReport = Rootect.analyze(
        this,
        RootectConfig(
            expectedSigningSha256 = EXPECTED_SIGNING_SHA256,
            // Costs a key generation, so a real app would run it on a considered check
            // rather than every screen. Enabled here because it is the strongest signal.
            hardwareAttestation = true,
        ),
    )

    /** Rebuilds the dashboard from a fresh scan. */
    private fun render() {
        val report = scan()
        container.removeAllViews()

        container.addView(banner(report))

        // Grouped by category so a verdict reads per concern rather than as one flat list.
        Category.entries
            .map { it to report.signalsIn(it) }
            .filter { (_, signals) -> signals.isNotEmpty() }
            .forEach { (category, signals) ->
                container.addView(sectionHeader(category.name, report.scoreFor(category)))
                signals.forEach { container.addView(signalRow(it)) }
            }

        if (report.signals.isEmpty()) {
            container.addView(note("No signals. Nothing suspicious was found."))
        }

        // Shown because "no signals" is weaker than it looks when checks could not run.
        if (report.inconclusiveChecks > 0) {
            container.addView(note("${report.inconclusiveChecks} check(s) could not complete."))
        }

        container.addView(rescanButton())
        container.addView(integrationSnippet())
    }

    /** Risk, score and the active rollups, coloured by severity. */
    private fun banner(report: RootectReport): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setBackgroundColor(colourFor(report.risk))
        setPadding(dp(20), dp(28), dp(20), dp(20))

        addView(text(report.risk.name, size = 30f, bold = true, colour = Color.WHITE))
        addView(text("score ${report.score} / 100", size = 15f, colour = 0xCCFFFFFF.toInt()))

        val verdicts = buildList {
            if (report.isRooted) add("rooted")
            if (report.isHooked) add("hooked")
            if (report.isTampered) add("tampered")
            if (report.isEmulator) add("emulator")
            if (report.isDebugged) add("debugged")
        }
        addView(
            text(
                if (verdicts.isEmpty()) "no verdicts raised" else verdicts.joinToString(" · "),
                size = 14f,
                bold = true,
                colour = Color.WHITE,
            ).apply { setPadding(0, dp(8), 0, 0) },
        )
    }

    /** Category name and that category's own score. */
    private fun sectionHeader(name: String, score: Int): View =
        text("$name — $score", size = 13f, bold = true, colour = MUTED).apply {
            setPadding(dp(20), dp(20), dp(20), dp(6))
        }

    /** One finding: its id, a confidence badge, and what it means. */
    private fun signalRow(signal: Signal): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(20), dp(10), dp(20), dp(10))

        addView(
            LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(text(signal.id.name, size = 15f, bold = true, colour = FOREGROUND))
                addView(badge(signal.confidence))
            },
        )
        addView(
            text(SignalCopy.of(signal.id), size = 13f, colour = MUTED)
                .apply { setPadding(0, dp(3), 0, 0) },
        )
    }

    /** Confidence chip, coloured by how hard the signal is to explain away. */
    private fun badge(confidence: Confidence): View =
        text(confidence.name, size = 11f, bold = true, colour = Color.WHITE).apply {
            setPadding(dp(8), dp(2), dp(8), dp(3))
            setBackgroundColor(colourFor(confidence))
            layoutParams = LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT)
                .apply { leftMargin = dp(10) }
        }

    /** Secondary line of text. */
    private fun note(message: String): View =
        text(message, size = 13f, colour = MUTED).apply {
            setPadding(dp(20), dp(16), dp(20), dp(4))
        }

    /** Re-runs the scan without restarting the app. */
    private fun rescanButton(): View = Button(this).apply {
        text = "Re-scan"
        // Conditions can be changed on a running app — attach Frida, toggle DenyList — and
        // the effect seen immediately. This is how the hook detection was verified.
        setOnClickListener { render() }
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
            setMargins(dp(16), dp(20), dp(16), dp(8))
        }
    }

    /** The dashboard doubles as the integration doc, so it shows its own call. */
    private fun integrationSnippet(): View = text(
        """
        val report = Rootect.analyze(context)

        report.risk        // SAFE .. CRITICAL
        report.score       // 0..100
        report.isRooted    // per-category rollups
        report.signals     // the evidence
        """.trimIndent(),
        size = 12f,
        colour = MUTED,
    ).apply {
        typeface = Typeface.MONOSPACE
        setBackgroundColor(SURFACE)
        setPadding(dp(20), dp(16), dp(20), dp(24))
    }

    /** Builds a styled TextView. */
    private fun text(
        value: String,
        size: Float,
        bold: Boolean = false,
        colour: Int = FOREGROUND,
    ): TextView = TextView(this).apply {
        text = value
        setTextSize(TypedValue.COMPLEX_UNIT_SP, size)
        setTextColor(colour)
        if (bold) setTypeface(typeface, Typeface.BOLD)
    }

    /** Density-independent pixels to device pixels. */
    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun colourFor(risk: RiskLevel): Int = when (risk) {
        RiskLevel.SAFE -> 0xFF2E7D32.toInt()
        RiskLevel.LOW -> 0xFF558B2F.toInt()
        RiskLevel.MEDIUM -> 0xFFF9A825.toInt()
        RiskLevel.HIGH -> 0xFFEF6C00.toInt()
        RiskLevel.CRITICAL -> 0xFFC62828.toInt()
    }

    private fun colourFor(confidence: Confidence): Int = when (confidence) {
        Confidence.WEAK -> 0xFF78909C.toInt()
        Confidence.MODERATE -> 0xFFF9A825.toInt()
        Confidence.STRONG -> 0xFFEF6C00.toInt()
        Confidence.CONCLUSIVE -> 0xFFC62828.toInt()
    }

    private companion object {
        const val BACKGROUND = 0xFFFAFAFA.toInt()
        const val SURFACE = 0xFFEEEEEE.toInt()
        const val FOREGROUND = 0xFF212121.toInt()
        const val MUTED = 0xFF616161.toInt()
    }
}
