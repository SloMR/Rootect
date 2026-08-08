package io.github.rootect.sample

import android.util.Base64
import io.github.rootect.RootectAttestation
import io.github.rootect.RootectReport
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONArray
import org.json.JSONObject

/**
 * The pattern worth copying.
 *
 * Everything on the dashboard was decided on a device an attacker may own, so it can be
 * rewritten. This sends hardware-signed evidence to a server that decides instead — and
 * sends the local report with it, so a client claiming to be clean while its own hardware
 * says otherwise convicts itself.
 */
internal object Verifier {

    // Loopback, reached through `adb reverse`, so the same address works on a phone and an
    // emulator. A real app points this at its own backend over TLS.
    private const val BASE = "http://127.0.0.1:8080"

    /** Blocking. Returns text to show the user. Call it off the main thread. */
    fun verify(report: RootectReport?): String = try {
        val challenge = JSONObject(httpGet("$BASE/challenge")).getString("challenge")

        // The challenge comes from the server and is used once, so a chain captured
        // earlier cannot be replayed.
        val chain = RootectAttestation.chain(challenge.hexToBytes())
        if (chain == null) {
            "NOT TRUSTED\n\nThis device would not produce a hardware attestation."
        } else {
            describe(JSONObject(httpPost("$BASE/verify", requestBody(challenge, chain, report))))
        }
    } catch (e: IOException) {
        "Could not reach the verifier.\n\n" +
            "python scripts/mock-verifier.py\n" +
            "adb reverse tcp:8080 tcp:8080\n\n(${e.message})"
    } catch (e: Exception) {
        "Verification failed: ${e.javaClass.simpleName}"
    }

    /** The server's verdict and why. */
    private fun describe(response: JSONObject): String {
        val reasons = response.getJSONArray("reasons")
        return buildString {
            append(if (response.getBoolean("trusted")) "TRUSTED" else "NOT TRUSTED")
            append("\n\n${response.getInt("certificates")} certificates checked")
            for (i in 0 until reasons.length()) append("\n• ${reasons.getString(i)}")
        }
    }

    /** The chain plus what this device believes, so the server can compare the two. */
    private fun requestBody(
        challenge: String,
        chain: List<ByteArray>,
        report: RootectReport?,
    ): String = JSONObject().apply {
        put("challenge", challenge)
        put("chain", JSONArray(chain.map { Base64.encodeToString(it, Base64.NO_WRAP) }))
        put(
            "clientReport",
            JSONObject().apply {
                put("risk", report?.risk?.name)
                put("isRooted", report?.isRooted)
                put("signals", JSONArray(report?.signals?.map { it.id.name } ?: emptyList<String>()))
            },
        )
    }.toString()

    private fun httpGet(url: String): String =
        (URL(url).openConnection() as HttpURLConnection).run {
            connectTimeout = TIMEOUT
            readTimeout = TIMEOUT
            try {
                inputStream.bufferedReader().readText()
            } finally {
                disconnect()
            }
        }

    private fun httpPost(url: String, body: String): String =
        (URL(url).openConnection() as HttpURLConnection).run {
            requestMethod = "POST"
            doOutput = true
            connectTimeout = TIMEOUT
            readTimeout = TIMEOUT * 2
            setRequestProperty("Content-Type", "application/json")
            try {
                outputStream.use { it.write(body.toByteArray()) }
                inputStream.bufferedReader().readText()
            } finally {
                disconnect()
            }
        }

    /** Hex to bytes, so the challenge goes back to the server byte-identical. */
    private fun String.hexToBytes(): ByteArray =
        ByteArray(length / 2) { substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private const val TIMEOUT = 4000
}
