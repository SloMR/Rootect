package io.github.rootect.sample

import android.util.Base64
import io.github.rootect.RootectAttestation
import io.github.rootect.RootectReport
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONArray
import org.json.JSONObject

internal enum class AttestationState { CHECKING, TRUSTED, REJECTED, UNAVAILABLE }

internal data class ServerDecision(
    val state: AttestationState,
    val title: String,
    val detail: String,
)

/**
 * The pattern worth copying.
 *
 * Everything on the dashboard was decided on a device an attacker may own, so it can be
 * rewritten. The hardware chain is the authoritative gate; the local report rides along as
 * explicitly untrusted runtime evidence the chain cannot see, so a lying client convicts itself.
 */
internal object Verifier {

    // Loopback, reached through `adb reverse`, so the same address works on a phone and an
    // emulator. A real app points this at its own backend over TLS.
    private const val BASE = "http://127.0.0.1:8080"

    /** Blocking. Call it off the main thread. Every failure denies access. */
    fun verify(report: RootectReport?): ServerDecision = try {
        val challenge = JSONObject(httpPost("$BASE/challenge", "{}")).getString("challenge")

        // The challenge comes from the server and is used once, so a chain captured
        // earlier cannot be replayed.
        val chain = RootectAttestation.chain(challenge.hexToBytes())
        if (chain == null) {
            unavailable(
                "Attestation unavailable",
                "This device did not provide hardware-backed evidence.",
            )
        } else {
            describe(JSONObject(httpPost("$BASE/verify", requestBody(challenge, chain, report))))
        }
    } catch (_: IOException) {
        unavailable(
            "Server unavailable",
            "The attestation server could not be reached. Protected access stays paused.",
        )
    } catch (_: Exception) {
        unavailable(
            "Verification unavailable",
            "The server response could not be verified. Protected access stays paused.",
        )
    }

    /** The server's verdict and why. */
    private fun describe(response: JSONObject): ServerDecision {
        val trusted = response.getBoolean("attestationTrusted")
        val reasons = response.getJSONArray("reasons")
        val detail = buildString {
            append("${response.getInt("certificates")} certificates checked")
            for (i in 0 until reasons.length()) append("\n• ${reasons.getString(i)}")
        }
        return ServerDecision(
            if (trusted) AttestationState.TRUSTED else AttestationState.REJECTED,
            if (trusted) "Device verified" else "Device rejected",
            detail,
        )
    }

    private fun unavailable(title: String, detail: String) =
        ServerDecision(AttestationState.UNAVAILABLE, title, detail)

    /** The hardware chain plus the untrusted local report, so the server can compare the two. */
    private fun requestBody(
        challenge: String,
        chain: List<ByteArray>,
        report: RootectReport?,
    ): String = JSONObject().apply {
        put("challenge", challenge)
        put("chain", JSONArray(chain.map { Base64.encodeToString(it, Base64.NO_WRAP) }))
        put(
            "report",
            JSONObject().apply {
                put("isRooted", report?.isRooted ?: false)
                put(
                    "signals",
                    JSONArray(report?.signals?.map { it.id.name } ?: emptyList<String>()),
                )
            },
        )
    }.toString()

    private fun httpPost(url: String, body: String): String =
        (URL(url).openConnection() as HttpURLConnection).run {
            requestMethod = "POST"
            doOutput = true
            connectTimeout = TIMEOUT
            readTimeout = TIMEOUT * 2
            setRequestProperty("Content-Type", "application/json")
            try {
                outputStream.use { it.write(body.toByteArray()) }
                val status = responseCode
                val response = (if (status in 200..299) inputStream else errorStream)
                    ?.bufferedReader()
                    ?.readText()
                    ?: throw IOException("empty server response")
                if (status >= 500) throw IOException("server unavailable")
                response
            } finally {
                disconnect()
            }
        }

    /** Hex to bytes, so the challenge goes back to the server byte-identical. */
    private fun String.hexToBytes(): ByteArray =
        ByteArray(length / 2) { substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private const val TIMEOUT = 4000
}
