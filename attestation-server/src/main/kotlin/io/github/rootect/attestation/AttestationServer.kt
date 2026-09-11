package io.github.rootect.attestation

import com.android.keyattestation.verifier.AttestationApplicationId
import com.android.keyattestation.verifier.AttributeConstraint
import com.android.keyattestation.verifier.GoogleTrustAnchors
import com.android.keyattestation.verifier.InstantSource
import com.android.keyattestation.verifier.VerificationResult
import com.android.keyattestation.verifier.VerifiedBootState
import com.android.keyattestation.verifier.Verifier
import com.android.keyattestation.verifier.challengecheckers.ChallengeMatcher
import com.android.keyattestation.verifier.constraintConfig
import com.google.gson.Gson
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.bodylimit.RequestBodyLimit
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStreamReader
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private const val MAX_CERTIFICATE_BYTES = 64 * 1024
private const val MAX_PENDING_CHALLENGES = 10_000
private const val MAX_REQUEST_BYTES = 768L * 1024
private const val REVOCATION_TIMEOUT_MS = 5_000
private val json = Gson()
private val googleRevocations = CachedRevocations(
    load = {
        fetchRevocations(
            URI.create("https://android.googleapis.com/attestation/status").toURL(),
            REVOCATION_TIMEOUT_MS,
        )
    },
)

// Google's verifier keeps only status == "REVOKED"; this also revokes SUSPENDED and every
// other non-"OK" status, and throws on malformed input so the cache reports unavailable.
private data class RevocationFeed(val entries: Map<String, RevocationEntry>?)

private data class RevocationEntry(val status: String?)

// Serials are matched against BigInteger.toString(16), so they are kept as lowercase hex.
internal fun parseRevocationFeed(body: String): Set<String> {
    val feed = json.fromJson(body, RevocationFeed::class.java)
        ?: throw IOException("revocation feed was empty")
    val entries = feed.entries ?: throw IOException("revocation feed had no entries object")
    return entries.entries
        .mapNotNull { (serial, entry) ->
            val status = entry?.status ?: throw IOException("revocation entry had no status")
            serial.lowercase().takeIf { status != "OK" }
        }
        .toSet()
}

private fun fetchRevocations(url: URL, timeoutMs: Int): Set<String> {
    val connection = (url.openConnection() as HttpURLConnection).apply {
        connectTimeout = timeoutMs
        readTimeout = timeoutMs
        requestMethod = "GET"
    }
    return try {
        if (connection.responseCode != HttpURLConnection.HTTP_OK) {
            throw IOException("revocation feed returned HTTP ${connection.responseCode}")
        }
        connection.inputStream.use { stream ->
            InputStreamReader(stream, Charsets.UTF_8).use { reader ->
                parseRevocationFeed(reader.readText())
            }
        }
    } finally {
        connection.disconnect()
    }
}

class AttestationPolicy(packageName: String, signerSha256: ByteArray, minimumVersion: Long) {
    private val packageName = packageName.also { require(it.isNotBlank()) }
    private val signerSha256 = signerSha256.copyOf().also { require(it.size == 32) }
    private val minimumVersion = minimumVersion.also { require(it >= 0) }

    internal fun matches(id: AttestationApplicationId?): Boolean =
        id != null &&
            id.packages.any {
                it.name == packageName && it.version >= BigInteger.valueOf(minimumVersion)
            } &&
            id.signatures.any { MessageDigest.isEqual(it.toByteArray(), signerSha256) }
}

data class AttestationVerdict(
    val attestationTrusted: Boolean,
    val reasons: List<String>,
    val certificates: Int,
)

// Untrusted client-reported evidence; never gates access. Nullable for lenient JSON parsing.
data class ClientReport(val isRooted: Boolean? = null)

// Client claims clean while its own validated chain reports unlocked/unverified.
internal fun contradicts(report: ClientReport?, hardwareCompromised: Boolean): Boolean =
    report?.isRooted == false && hardwareCompromised

fun interface EvidenceVerifier {
    fun verify(challenge: ByteArray, chainDer: List<ByteArray>?, report: ClientReport?): AttestationVerdict
}

class AttestationVerifier(
    policy: AttestationPolicy,
    private val consumeChallenge: (ByteArray) -> Boolean,
    revokedSerials: () -> Set<String> = googleRevocations::get,
    now: InstantSource = InstantSource { Instant.now() },
) : EvidenceVerifier {
    private val verifier = Verifier(
        GoogleTrustAnchors,
        revokedSerials,
        now,
        constraintConfig {
            additionalConstraint {
                AttributeConstraint.STRICT("App identity", true) {
                    policy.matches(it.softwareEnforced.attestationApplicationId)
                }
            }
        },
    )

    override fun verify(
        challenge: ByteArray,
        chainDer: List<ByteArray>?,
        report: ClientReport?,
    ): AttestationVerdict {
        val count = chainDer?.size ?: 0
        if (challenge.size != 32 || chainDer == null) return rejected("invalid input", count)
        val nonce = challenge.copyOf()
        val chain = runCatching { parseChain(chainDer) }
            .getOrElse { return rejected("invalid input", count) }
        if (!runCatching { consumeChallenge(nonce.copyOf()) }.getOrDefault(false)) {
            return rejected("challenge rejected", count)
        }

        val result = try {
            verifier.verify(chain, ChallengeMatcher(nonce))
        } catch (failure: RevocationUnavailableException) {
            throw failure
        } catch (_: Exception) {
            null
        }
        val success = result as? VerificationResult.Success
        val trusted = success != null &&
            success.deviceLocked &&
            success.verifiedBootState == VerifiedBootState.VERIFIED
        if (trusted) return AttestationVerdict(true, emptyList(), count)
        val reasons = buildList {
            add("attestation rejected")
            if (contradicts(report, success != null)) add("client contradicts hardware")
        }
        return AttestationVerdict(false, reasons, count)
    }

    private fun parseChain(chainDer: List<ByteArray>): List<X509Certificate> {
        require(chainDer.size in 2..8)
        val factory = CertificateFactory.getInstance("X.509")
        return chainDer.map { encoded ->
            require(encoded.size in 1..MAX_CERTIFICATE_BYTES)
            val input = ByteArrayInputStream(encoded.copyOf())
            (factory.generateCertificate(input) as X509Certificate).also {
                require(input.available() == 0)
            }
        }
    }

}

internal class CachedRevocations(
    private val load: () -> Set<String>,
    private val ttl: Duration = Duration.ofHours(1),
    private val now: () -> Instant = { Instant.now() },
) {
    private var value = emptySet<String>()
    private var expires = Instant.EPOCH

    init {
        require(!ttl.isZero && !ttl.isNegative)
    }

    @Synchronized
    fun get(): Set<String> {
        val timestamp = now()
        if (timestamp.isBefore(expires)) return value
        val loaded = try {
            load().toSet()
        } catch (failure: Exception) {
            throw RevocationUnavailableException(failure)
        }
        value = loaded
        expires = timestamp.plus(ttl)
        return loaded
    }
}

internal class RevocationUnavailableException(cause: Exception) : RuntimeException(cause)

interface ChallengeStore {
    fun issue(): ByteArray
    fun consumeIfFresh(challenge: ByteArray): Boolean
}

/** Local example only. Replace with an account-bound atomic Redis or database store. */
class InMemoryChallengeStore(
    private val ttl: Duration = Duration.ofMinutes(2),
    private val now: () -> Instant = { Instant.now() },
    private val random: SecureRandom = SecureRandom(),
) : ChallengeStore {
    private val pending = ConcurrentHashMap<String, Instant>()

    init {
        require(!ttl.isZero && !ttl.isNegative)
    }

    override fun issue(): ByteArray {
        val timestamp = now()
        pending.entries.removeIf { !timestamp.isBefore(it.value) }
        check(pending.size < MAX_PENDING_CHALLENGES) { "challenge capacity reached" }
        while (true) {
            val value = ByteArray(32).also(random::nextBytes)
            if (pending.putIfAbsent(value.toHex(), timestamp.plus(ttl)) == null) return value
        }
    }

    override fun consumeIfFresh(challenge: ByteArray): Boolean {
        if (challenge.size != 32) return false
        val timestamp = now()
        var accepted = false
        pending.computeIfPresent(challenge.toHex()) { _, expires ->
            accepted = timestamp.isBefore(expires)
            null
        }
        return accepted
    }
}

fun Application.attestationApi(store: ChallengeStore, verifier: EvidenceVerifier) {
    routing {
        install(RequestBodyLimit) { bodyLimit { MAX_REQUEST_BYTES } }

        get("/health") {
            call.respondJson(HttpStatusCode.OK, mapOf("ok" to true))
        }

        post("/challenge") {
            val challenge = runCatching(store::issue).getOrNull()
            if (challenge == null) {
                call.respondJson(HttpStatusCode.ServiceUnavailable, mapOf("error" to "unavailable"))
                return@post
            }
            call.respondJson(HttpStatusCode.OK, mapOf("challenge" to challenge.toHex()))
        }

        post("/verify") {
            val request = runCatching { decodeRequest(call.receiveText()) }.getOrNull()
            if (request == null) {
                call.respondJson(HttpStatusCode.BadRequest, rejected("invalid input"))
                return@post
            }
            val verdict = try {
                withContext(Dispatchers.IO) {
                    verifier.verify(request.challenge, request.chain, request.report)
                }
            } catch (_: RevocationUnavailableException) {
                call.respondJson(
                    HttpStatusCode.ServiceUnavailable,
                    mapOf("error" to "unavailable"),
                )
                return@post
            }
            call.respondJson(HttpStatusCode.OK, verdict)
        }
    }
}

fun main() {
    val policy = AttestationPolicy(
        requiredEnvironment("ROOTECT_APP_ID"),
        requiredEnvironment("ROOTECT_SIGNING_SHA256").hexBytes(32)
            ?: error("ROOTECT_SIGNING_SHA256 must contain 64 hexadecimal characters"),
        requiredEnvironment("ROOTECT_MIN_VERSION").toLongOrNull()
            ?: error("ROOTECT_MIN_VERSION must be a non-negative integer"),
    )
    val ttl = System.getenv("ROOTECT_CHALLENGE_TTL_SECONDS")?.toLongOrNull() ?: 120
    val store = InMemoryChallengeStore(Duration.ofSeconds(ttl))
    val verifier = AttestationVerifier(policy, store::consumeIfFresh)
    val host = System.getenv("HOST")?.takeIf(String::isNotBlank) ?: "127.0.0.1"
    val port = System.getenv("PORT")?.toIntOrNull() ?: 8080
    embeddedServer(Netty, host = host, port = port) {
        attestationApi(store, verifier)
    }.start(wait = true)
}

private data class VerifyRequest(
    val challenge: String?,
    val chain: List<String>?,
    val report: ClientReport?,
)
private data class DecodedRequest(
    val challenge: ByteArray,
    val chain: List<ByteArray>,
    val report: ClientReport?,
)

private fun decodeRequest(body: String): DecodedRequest {
    val request = requireNotNull(json.fromJson(body, VerifyRequest::class.java))
    val challenge = requireNotNull(request.challenge?.hexBytes(32))
    val encodedChain = requireNotNull(request.chain)
    require(encodedChain.size in 2..8)
    val chain = encodedChain.map {
        Base64.getDecoder().decode(it).also { der ->
            require(der.size in 1..MAX_CERTIFICATE_BYTES)
        }
    }
    return DecodedRequest(challenge, chain, request.report)
}

private suspend fun ApplicationCall.respondJson(status: HttpStatusCode, value: Any) {
    response.headers.append(HttpHeaders.CacheControl, "no-store")
    respondText(json.toJson(value), ContentType.Application.Json, status)
}

private fun rejected(reason: String, count: Int = 0) =
    AttestationVerdict(false, listOf(reason), count)

private fun requiredEnvironment(name: String): String =
    System.getenv(name)?.trim()?.takeIf(String::isNotEmpty) ?: error("$name is required")

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

private fun String.hexBytes(size: Int): ByteArray? {
    val compact = replace(":", "")
    if (compact.length != size * 2 || compact.any { it.digitToIntOrNull(16) == null }) return null
    return ByteArray(size) {
        compact.substring(it * 2, it * 2 + 2).toInt(16).toByte()
    }
}
