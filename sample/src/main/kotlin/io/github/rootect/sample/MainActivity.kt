package io.github.rootect.sample

import android.app.Activity
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
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
import io.github.rootect.RiskLevel
import io.github.rootect.Rootect
import io.github.rootect.RootectConfig
import io.github.rootect.RootectReport
import io.github.rootect.signal.Category
import io.github.rootect.signal.Confidence
import io.github.rootect.signal.Signal

private val EXPECTED_SIGNING_SHA256 = BuildConfig.ROOTECT_SIGNING_SHA256.ifEmpty { null }

/**
 * Live dashboard for a Rootect scan.
 *
 * Plain views and no UI dependencies. Local evidence comes from [scan]; protected access
 * comes from the separate server-attestation flow.
 */
class MainActivity : Activity() {

    private lateinit var container: LinearLayout
    private var lastReport: RootectReport? = null
    private var serverDecision = ServerDecision(
        AttestationState.CHECKING,
        "Preparing verification",
        "Protected access stays paused until the server answers.",
    )
    private var verificationInFlight = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        actionBar?.hide()
        tintSystemBars()

        container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(BACKGROUND)
            setPadding(0, 0, 0, dp(24))
        }
        setContentView(
            ScrollView(this).apply {
                isFillViewport = true
                setBackgroundColor(BACKGROUND)
                addView(container)
            },
        )
        rescan()
        verifyOffDevice()
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

    /** Refreshes local evidence without changing the server decision. */
    private fun rescan() {
        val report = scan()
        lastReport = report
        if (report.isRooted) LocalSecurityHistory.rememberRootDetection(this)
        render()
    }

    /** Rebuilds the dashboard from its current local and server state. */
    private fun render() {
        val report = lastReport ?: return
        container.removeAllViews()

        container.addView(appHeader())
        container.addView(banner(report))
        container.addView(
            sectionHeading(
                "LOCAL EVIDENCE",
                "Signals reported by this app process.",
            ),
        )

        Category.entries
            .map { it to report.signalsIn(it) }
            .filter { (_, signals) -> signals.isNotEmpty() }
            .forEach { (category, signals) ->
                container.addView(categoryCard(category, signals, report.scoreFor(category)))
            }

        if (report.signals.isEmpty()) {
            container.addView(
                messageCard(
                    "No local signals",
                    "This process reported no evidence. That is not proof the device is clean.",
                    CARD,
                    DIVIDER,
                ),
            )
        }

        if (report.inconclusiveChecks > 0) {
            container.addView(
                messageCard(
                    "Incomplete scan",
                    "${report.inconclusiveChecks} check(s) could not complete.",
                    WARNING_FILL,
                    WARNING_ACCENT,
                ),
            )
        }

        container.addView(rescanButton())
        container.addView(
            sectionHeading(
                "HARDWARE ATTESTATION",
                "Fresh evidence checked outside this process.",
            ),
        )
        container.addView(attestationPanel())
        container.addView(
            sectionHeading(
                "LOCAL SECURITY HISTORY",
                "Encrypted memory for this installation only.",
            ),
        )
        container.addView(historyPanel())
        container.addView(footerNote())
    }

    private fun appHeader(): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setBackgroundColor(HEADER)
        setPadding(dp(20), dp(22), dp(20), dp(24))
        addView(text("ROOTECT", size = 12f, bold = true, colour = HEADER_ACCENT).apply {
            letterSpacing = 0.16f
        })
        addView(text("Device integrity", size = 28f, bold = true, colour = Color.WHITE).apply {
            setPadding(0, dp(5), 0, dp(4))
        })
        addView(
            text(
                "Local diagnostics with an independent server verdict.",
                size = 14f,
                colour = HEADER_MUTED,
            ),
        )
    }

    private fun attestationPanel(): View = LinearLayout(this).apply {
        val accent = attestationAccent()
        orientation = LinearLayout.VERTICAL
        background = panelBackground(attestationFill(), accent)
        elevation = dp(2).toFloat()
        setPadding(dp(18), dp(20), dp(18), dp(18))
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
            setMargins(dp(16), dp(6), dp(16), dp(12))
        }
        addView(
            LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(statusDot(accent))
                addView(text("SERVER-GATED", size = 11f, bold = true, colour = accent).apply {
                    letterSpacing = 0.12f
                    setPadding(dp(9), 0, 0, 0)
                })
            },
        )
        addView(text(serverDecision.title, size = 23f, bold = true).apply {
            setPadding(0, dp(12), 0, dp(5))
        })
        addView(
            text(
                when (serverDecision.state) {
                    AttestationState.TRUSTED -> "Protected access granted"
                    AttestationState.REJECTED -> "Protected access denied"
                    AttestationState.CHECKING -> "Protected access paused"
                    AttestationState.UNAVAILABLE -> "Protected access unavailable"
                },
                size = 14f,
                bold = true,
                colour = accent,
            ),
        )
        addView(text(serverDecision.detail, size = 13f, colour = MUTED).apply {
            setPadding(0, dp(12), 0, 0)
            setLineSpacing(0f, 1.15f)
        })
        addView(verifyButton())
    }

    private fun historyPanel(): View {
        val history = LocalSecurityHistory.read(this)
        val events = listOfNotNull(
            "root detected".takeIf { history.rootDetected },
            "attestation rejected".takeIf { history.attestationRejected },
        ).joinToString(" · ")
        val flagged = !history.readable || history.persistenceFailed || history.hasEvents
        return messageCard(
            when {
                !history.readable -> "Local record unreadable"
                history.persistenceFailed -> "Local record not saved"
                history.hasEvents -> "Security event remembered"
                else -> "No recorded events"
            },
            when {
                !history.readable ->
                    "The encrypted record exists but could not be read or decrypted."
                history.persistenceFailed && history.hasEvents ->
                    "$events. A recent event could not be durably saved."
                history.persistenceFailed ->
                    "Could not read or save the local record."
                history.hasEvents ->
                    "$events. Survives restarts, but root or reinstall can erase it. The backend remains authoritative."
                else -> "A root verdict or server rejection will be encrypted here with Android Keystore."
            },
            if (flagged) WARNING_FILL else CARD,
            if (flagged) WARNING_ACCENT else DIVIDER,
        )
    }

    private fun banner(report: RootectReport): View = LinearLayout(this).apply {
        val risk = if (serverDecision.state == AttestationState.REJECTED) {
            RiskLevel.CRITICAL
        } else {
            report.risk
        }
        val label = when (serverDecision.state) {
            AttestationState.CHECKING -> "VERIFYING"
            AttestationState.UNAVAILABLE -> "UNVERIFIED"
            else -> risk.name
        }
        val bannerColour = when (serverDecision.state) {
            AttestationState.CHECKING,
            AttestationState.UNAVAILABLE -> WARNING_BANNER
            else -> colourFor(risk)
        }
        orientation = LinearLayout.VERTICAL
        background = panelBackground(bannerColour, bannerColour)
        elevation = dp(3).toFloat()
        setPadding(dp(20), dp(22), dp(20), dp(20))
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
            setMargins(dp(16), dp(16), dp(16), dp(8))
        }

        addView(text("SECURITY STATUS", size = 11f, bold = true, colour = WHITE_MUTED).apply {
            letterSpacing = 0.14f
        })
        addView(text(label, size = 34f, bold = true, colour = Color.WHITE).apply {
            setPadding(0, dp(5), 0, dp(2))
        })
        addView(
            text(
                when (serverDecision.state) {
                    AttestationState.CHECKING -> "Waiting for hardware attestation"
                    AttestationState.REJECTED -> "Hardware attestation rejected by the server"
                    AttestationState.UNAVAILABLE -> "Attestation server unavailable"
                    AttestationState.TRUSTED -> "Hardware verified · local score ${report.score} / 100"
                },
                size = 14f,
                colour = WHITE_MUTED,
            ),
        )

        val verdicts = buildList {
            when (serverDecision.state) {
                AttestationState.CHECKING -> add("protected access paused")
                AttestationState.TRUSTED -> add("hardware verified")
                AttestationState.REJECTED -> add("attestation rejected")
                AttestationState.UNAVAILABLE -> add("protected access paused")
            }
            if (report.isRooted) add("rooted")
            if (report.isHooked) add("hooked")
            if (report.isTampered) add("tampered")
            if (report.isEmulator) add("emulator")
            if (report.isDebugged) add("debugged")
        }
        addView(
            text(
                when {
                    verdicts.isNotEmpty() -> verdicts.joinToString(" · ")
                    report.signals.isEmpty() -> "no local verdicts raised"
                    else -> "local evidence needs review"
                },
                size = 13f,
                bold = true,
                colour = Color.WHITE,
            ).apply { setPadding(0, dp(12), 0, 0) },
        )
    }

    private fun sectionHeading(title: String, subtitle: String): View =
        LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(22), dp(20), dp(8))
            addView(text(title, size = 12f, bold = true, colour = FOREGROUND).apply {
                letterSpacing = 0.12f
            })
            addView(text(subtitle, size = 13f, colour = MUTED).apply {
                setPadding(0, dp(3), 0, 0)
            })
        }

    private fun categoryCard(category: Category, signals: List<Signal>, score: Int): View =
        LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = panelBackground(CARD, DIVIDER)
            elevation = dp(1).toFloat()
            setPadding(dp(16), dp(15), dp(16), dp(8))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
                setMargins(dp(16), dp(6), dp(16), dp(6))
            }
            addView(
                LinearLayout(context).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                    addView(text(category.name, size = 13f, bold = true).apply {
                        letterSpacing = 0.08f
                        layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)
                    })
                    addView(scoreBadge(score))
                },
            )
            signals.forEach {
                addView(divider())
                addView(signalRow(it))
            }
        }

    private fun signalRow(signal: Signal): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(0, dp(13), 0, dp(12))

        addView(
            LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.TOP
                addView(text(signal.id.name.replace("_", "_\u200B"), size = 14f, bold = true).apply {
                    typeface = Typeface.MONOSPACE
                    layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)
                })
                addView(badge(signal.confidence))
            },
        )
        addView(
            text(SignalCopy.of(signal.id), size = 13f, colour = MUTED).apply {
                setPadding(0, dp(6), 0, 0)
                setLineSpacing(0f, 1.1f)
            },
        )
    }

    private fun badge(confidence: Confidence): View =
        text(confidence.name, size = 10f, bold = true, colour = Color.WHITE).apply {
            isSingleLine = true
            setPadding(dp(8), dp(3), dp(8), dp(3))
            background = pillBackground(colourFor(confidence))
            layoutParams = LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT)
                .apply { leftMargin = dp(10) }
        }

    private fun scoreBadge(score: Int): View =
        text("$score / 100", size = 11f, bold = true, colour = PRIMARY).apply {
            isSingleLine = true
            setPadding(dp(9), dp(4), dp(9), dp(4))
            background = pillBackground(PRIMARY_FILL)
        }

    private fun messageCard(title: String, message: String, fill: Int, accent: Int): View =
        LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = panelBackground(fill, accent)
            setPadding(dp(16), dp(15), dp(16), dp(15))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
                setMargins(dp(16), dp(6), dp(16), dp(6))
            }
            addView(text(title, size = 14f, bold = true))
            addView(text(message, size = 13f, colour = MUTED).apply {
                setPadding(0, dp(5), 0, 0)
            })
        }

    private fun divider(): View = View(this).apply {
        setBackgroundColor(DIVIDER)
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, dp(1)).apply {
            topMargin = dp(12)
        }
    }

    private fun rescanButton(): View = Button(this).apply {
        text = "Re-scan"
        isAllCaps = false
        backgroundTintList = ColorStateList.valueOf(PRIMARY)
        setTextColor(Color.WHITE)
        setOnClickListener { rescan() }
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
            setMargins(dp(16), dp(12), dp(16), dp(4))
        }
    }

    private fun verifyButton(): View = Button(this).apply {
        text = if (verificationInFlight) {
            "Checking…"
        } else {
            "Verify again"
        }
        isAllCaps = false
        isEnabled = !verificationInFlight
        backgroundTintList = ColorStateList.valueOf(attestationAccent())
        setTextColor(Color.WHITE)
        setOnClickListener { verifyOffDevice() }
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
            setMargins(0, dp(16), 0, 0)
        }
    }

    private fun verifyOffDevice() {
        if (verificationInFlight) return
        verificationInFlight = true
        val report = lastReport
        serverDecision = ServerDecision(
            AttestationState.CHECKING,
            "Checking server",
            "Generating fresh hardware evidence. Protected access stays paused.",
        )
        render()
        Thread {
            val decision = Verifier.verify(report)
            if (decision.state == AttestationState.REJECTED) {
                LocalSecurityHistory.rememberAttestationRejection(applicationContext)
            }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                serverDecision = decision
                verificationInFlight = false
                render()
            }
        }.start()
    }

    private fun footerNote(): View =
        text(
            "Security decisions must be enforced by the backend. This screen is diagnostic.",
            size = 12f,
            colour = MUTED,
        ).apply {
            gravity = Gravity.CENTER
            setPadding(dp(24), dp(12), dp(24), dp(8))
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

    @Suppress("DEPRECATION")
    private fun tintSystemBars() {
        window.statusBarColor = HEADER
        window.navigationBarColor = HEADER
    }

    private fun panelBackground(fill: Int, stroke: Int) = GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = dp(18).toFloat()
        setColor(fill)
        setStroke(dp(1), stroke)
    }

    private fun pillBackground(fill: Int) = GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = dp(99).toFloat()
        setColor(fill)
    }

    private fun statusDot(colour: Int): View = View(this).apply {
        background = GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            setColor(colour)
        }
        layoutParams = LinearLayout.LayoutParams(dp(10), dp(10))
    }

    private fun attestationFill(): Int = when (serverDecision.state) {
        AttestationState.TRUSTED -> TRUSTED_FILL
        AttestationState.REJECTED -> REJECTED_FILL
        AttestationState.CHECKING,
        AttestationState.UNAVAILABLE -> WARNING_FILL
    }

    private fun attestationAccent(): Int = when (serverDecision.state) {
        AttestationState.TRUSTED -> TRUSTED_ACCENT
        AttestationState.REJECTED -> REJECTED_ACCENT
        AttestationState.CHECKING,
        AttestationState.UNAVAILABLE -> WARNING_ACCENT
    }

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
        const val BACKGROUND = 0xFFF4F6F8.toInt()
        const val CARD = 0xFFFFFFFF.toInt()
        const val HEADER = 0xFF111827.toInt()
        const val HEADER_ACCENT = 0xFF93C5FD.toInt()
        const val HEADER_MUTED = 0xFFCBD5E1.toInt()
        const val FOREGROUND = 0xFF111827.toInt()
        const val MUTED = 0xFF5F6B7A.toInt()
        const val DIVIDER = 0xFFE2E8F0.toInt()
        const val PRIMARY = 0xFF2563EB.toInt()
        const val PRIMARY_FILL = 0xFFEFF6FF.toInt()
        const val TRUSTED_FILL = 0xFFECFDF3.toInt()
        const val TRUSTED_ACCENT = 0xFF067647.toInt()
        const val REJECTED_FILL = 0xFFFEF3F2.toInt()
        const val REJECTED_ACCENT = 0xFFB42318.toInt()
        const val WARNING_FILL = 0xFFFFFAEB.toInt()
        const val WARNING_ACCENT = 0xFFB54708.toInt()
        const val WARNING_BANNER = 0xFFA16207.toInt()
        const val WHITE_MUTED = 0xFFDCE5F0.toInt()
    }
}
