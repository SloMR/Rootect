package io.github.rootect.attestation

import com.android.keyattestation.verifier.AttestationApplicationId
import com.android.keyattestation.verifier.AttestationPackageInfo
import com.android.keyattestation.verifier.GoogleTrustAnchors
import com.google.gson.Gson
import com.google.protobuf.ByteString
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import java.math.BigInteger
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AttestationServerTest {
    private val json = Gson()
    private val signer = ByteArray(32) { it.toByte() }
    private val policy = AttestationPolicy("io.github.rootect.demo", signer, 2)

    @Test
    fun appIdentityMustMatchPackageVersionAndSigner() {
        assertTrue(policy.matches(identity()))
        assertFalse(policy.matches(identity(packageName = "other.app")))
        assertFalse(policy.matches(identity(version = 1)))
        assertFalse(policy.matches(identity(signer = ByteArray(32))))
    }

    @Test
    fun policyRejectsInvalidValues() {
        assertFails { AttestationPolicy("", signer, 2) }
        assertFails { AttestationPolicy("app", ByteArray(31), 2) }
        assertFails { AttestationPolicy("app", signer, -1) }
    }

    @Test
    fun malformedInputFailsBeforeChallengeConsumption() {
        var consumed = false
        val verifier = AttestationVerifier(policy, { consumed = true; true }, { emptySet() })
        assertFalse(verifier.verify(ByteArray(32), listOf(ByteArray(1)), null).attestationTrusted)
        assertFalse(consumed)
    }

    @Test
    fun revocationOutageDoesNotConsumeTheChallenge() {
        var consumed = false
        val certificate = GoogleTrustAnchors().first().trustedCert.encoded
        val verifier = AttestationVerifier(
            policy,
            { consumed = true; true },
            { throw RevocationUnavailableException(IllegalStateException("offline")) },
        )

        assertFailsWith<RevocationUnavailableException> {
            verifier.verify(ByteArray(32), List(2) { certificate }, null)
        }
        assertFalse(consumed)
    }

    @Test
    fun challengeIsConsumedOnce() {
        val unused = AtomicBoolean(true)
        val certificate = GoogleTrustAnchors().first().trustedCert.encoded
        val verifier = AttestationVerifier(policy, { unused.getAndSet(false) }, { emptySet() })
        assertEquals("attestation rejected", verifier.verify(ByteArray(32), List(2) { certificate }, null).reasons.single())
        assertEquals("challenge rejected", verifier.verify(ByteArray(32), List(2) { certificate }, null).reasons.single())
    }

    @Test
    fun challengeStoreExpiresAndConsumesAtomically() {
        var now = Instant.EPOCH
        val store = InMemoryChallengeStore(Duration.ofSeconds(1), { now })
        val first = store.issue()
        assertTrue(store.consumeIfFresh(first))
        assertFalse(store.consumeIfFresh(first))
        val second = store.issue()
        now = now.plusSeconds(2)
        assertFalse(store.consumeIfFresh(second))
    }

    @Test
    fun revocationsAreCachedUntilExpiry() {
        var now = Instant.EPOCH
        var loads = 0
        val source = CachedRevocations(
            { setOf((++loads).toString()) },
            refreshAfter = Duration.ofSeconds(1),
            now = { now },
        )

        assertEquals(setOf("1"), source.get())
        assertEquals(setOf("1"), source.get())
        now = now.plusSeconds(1)
        assertEquals(setOf("2"), source.get())
    }

    @Test
    fun revocationFeedIncludesRevokedAndSuspended() {
        val body =
            """{"entries":{"aa":{"status":"REVOKED"},"bb":{"status":"SUSPENDED"},"cc":{"status":"OK"}}}"""
        assertEquals(setOf("aa", "bb"), parseRevocationFeed(body))
    }

    @Test
    fun revocationFeedFailsClosedOnUnknownStatusAndLowercasesSerials() {
        // An unrecognised status must not be silently trusted, and serials must match
        // BigInteger.toString(16), which is lowercase.
        assertEquals(
            setOf("abcdef"),
            parseRevocationFeed("""{"entries":{"ABCDEF":{"status":"COMPROMISED"}}}"""),
        )
    }

    @Test
    fun emptyRevocationFeedIsValidButMalformedThrows() {
        assertEquals(emptySet<String>(), parseRevocationFeed("""{"entries":{}}"""))
        assertFails { parseRevocationFeed("not json") }
        assertFails { parseRevocationFeed("{}") } // no entries object
        assertFails { parseRevocationFeed("""{"entries":{"aa":{}}}""") } // entry without status
    }

    private fun outageSource(now: () -> Instant, offline: () -> Boolean) = CachedRevocations(
        { if (offline()) throw IllegalStateException("offline") else setOf("aa") },
        refreshAfter = Duration.ofSeconds(1),
        maxStale = Duration.ofSeconds(10),
        retryAfter = Duration.ofSeconds(2),
        now = now,
    )

    @Test
    fun cachedRevocationsServeLastKnownGoodThroughAShortOutage() {
        var now = Instant.EPOCH
        var offline = false
        val source = outageSource({ now }, { offline })
        assertEquals(setOf("aa"), source.get())
        now = now.plusSeconds(2) // past refreshAfter
        offline = true
        assertEquals(setOf("aa"), source.get()) // serves last-known-good, not 503
    }

    @Test
    fun cachedRevocationsFailClosedOnceTooStale() {
        var now = Instant.EPOCH
        var offline = false
        val source = outageSource({ now }, { offline })
        assertEquals(setOf("aa"), source.get())
        now = now.plusSeconds(11) // past maxStale
        offline = true
        assertFails { source.get() } // too old to trust → fails closed
    }

    @Test
    fun cachedRevocationsFailClosedWithNoListYet() {
        // Cold start with Google already down: no last-known-good to fall back on.
        assertFails { CachedRevocations({ throw IllegalStateException("offline") }).get() }
    }

    @Test
    fun clientRootClaimsCannotChangeTheHardwareVerdict() {
        for (trusted in listOf(false, true)) {
            val verdicts = listOf(null, ClientReport(), ClientReport(false), ClientReport(true))
                .map { verdictForHardware(trusted, 2, it) }
            assertTrue(verdicts.all { it.attestationTrusted == trusted })
            assertTrue(verdicts.all {
                it.reasons == if (trusted) emptyList() else listOf("attestation rejected")
            })
        }
    }

    @Test
    fun malformedUntrustedChainCannotBeMadeTrustedByClientClaims() {
        val certificate = GoogleTrustAnchors().first().trustedCert.encoded
        val verifier = AttestationVerifier(policy, { true }, { emptySet() })
        for (report in listOf(null, ClientReport(), ClientReport(false), ClientReport(true))) {
            val verdict = verifier.verify(ByteArray(32), List(2) { certificate }, report)
            assertFalse(verdict.attestationTrusted)
            assertEquals(listOf("attestation rejected"), verdict.reasons)
        }
    }

    @Test
    fun reportedSignalsAreEchoedAndCannotChangeTheVerdict() {
        val certificate = GoogleTrustAnchors().first().trustedCert.encoded
        val verifier = AttestationVerifier(policy, { true }, { emptySet() })
        val report = ClientReport(
            isRooted = false,
            signals = listOf(
                "FRIDA_LIBRARY_MAPPED",
                "FRIDA_LIBRARY_MAPPED",
                "not a signal",
                "../etc",
                "A".repeat(65),
            ),
        )

        val verdict = verifier.verify(ByteArray(32), List(2) { certificate }, report)

        assertFalse(verdict.attestationTrusted)
        assertEquals(listOf("attestation rejected"), verdict.reasons)
        assertEquals(listOf("FRIDA_LIBRARY_MAPPED"), verdict.reportedSignals)
    }

    @Test
    fun nullSignalNamesAreDiscardedAfterChallengeConsumption() {
        val certificate = GoogleTrustAnchors().first().trustedCert.encoded
        var consumed = false
        val verifier = AttestationVerifier(policy, { consumed = true; true }, { emptySet() })
        val report = json.fromJson(
            """{"signals":[null,"FRIDA_LIBRARY_MAPPED"]}""",
            ClientReport::class.java,
        )

        val verdict = verifier.verify(ByteArray(32), List(2) { certificate }, report)
        assertTrue(consumed)
        assertEquals(listOf("FRIDA_LIBRARY_MAPPED"), verdict.reportedSignals)
    }

    @Test
    fun customRevocationSupplierFailureRemainsServiceUnavailable() {
        val certificate = GoogleTrustAnchors().first().trustedCert.encoded
        var consumed = false
        val verifier = AttestationVerifier(policy, { consumed = true; true },
            { throw IllegalStateException("offline") })

        assertFailsWith<RevocationUnavailableException> {
            verifier.verify(ByteArray(32), List(2) { certificate }, null)
        }
        assertFalse(consumed)
    }

    @Test
    fun theClientReportReachesTheVerifier() = testApplication {
        val store = InMemoryChallengeStore()
        val verifier = EvidenceVerifier { _, _, report ->
            AttestationVerdict(false, listOf(if (report?.isRooted == false) "reported clean" else "no report"), 0)
        }
        application { attestationApi(store, verifier) }

        val challenge = json.fromJson(
            client.post("/challenge").bodyAsText(),
            Map::class.java,
        )["challenge"] as String
        val cert = Base64.getEncoder().encodeToString(byteArrayOf(1))
        val body = json.toJson(
            mapOf("challenge" to challenge, "chain" to List(2) { cert }, "report" to mapOf("isRooted" to false)),
        )
        val resp = client.post("/verify") {
            contentType(ContentType.Application.Json); setBody(body)
        }
        assertEquals(
            listOf("reported clean"),
            json.fromJson(resp.bodyAsText(), Map::class.java)["reasons"],
        )
    }

    @Test
    fun routesIssueVerifyAndRejectReplay() = testApplication {
        val store = InMemoryChallengeStore()
        val verifier = EvidenceVerifier { challenge, chain, _ ->
            val trusted = store.consumeIfFresh(challenge)
            AttestationVerdict(
                trusted,
                if (trusted) emptyList() else listOf("challenge rejected"),
                chain?.size ?: 0,
            )
        }
        application { attestationApi(store, verifier) }

        val issued = client.post("/challenge")
        assertEquals(HttpStatusCode.OK, issued.status)
        val challenge = json.fromJson(issued.bodyAsText(), Map::class.java)["challenge"] as String
        val certificate = Base64.getEncoder().encodeToString(byteArrayOf(1))
        val body = json.toJson(mapOf("challenge" to challenge, "chain" to List(2) { certificate }))
        val first = client.post("/verify") { contentType(ContentType.Application.Json); setBody(body) }
        val replay = client.post("/verify") { contentType(ContentType.Application.Json); setBody(body) }

        assertEquals(HttpStatusCode.OK, first.status)
        assertTrue(json.fromJson(first.bodyAsText(), Map::class.java)["attestationTrusted"] as Boolean)
        assertFalse(json.fromJson(replay.bodyAsText(), Map::class.java)["attestationTrusted"] as Boolean)
    }

    @Test
    fun malformedHttpRequestIsRejected() = testApplication {
        application {
            attestationApi(InMemoryChallengeStore(), EvidenceVerifier { _, _, _ -> error("called") })
        }
        val response = client.post("/verify") {
            contentType(ContentType.Application.Json)
            setBody("{}")
        }
        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertFalse(json.fromJson(response.bodyAsText(), Map::class.java)["attestationTrusted"] as Boolean)
    }

    @Test
    fun verifierFailureIsUnavailable() = testApplication {
        val store = InMemoryChallengeStore()
        application {
            attestationApi(
                store,
                EvidenceVerifier { _, _, _ ->
                    throw RevocationUnavailableException(IllegalStateException("offline"))
                },
            )
        }
        val challenge = json.fromJson(
            client.post("/challenge").bodyAsText(),
            Map::class.java,
        )["challenge"] as String
        val certificate = Base64.getEncoder().encodeToString(byteArrayOf(1))
        val response = client.post("/verify") {
            contentType(ContentType.Application.Json)
            setBody(json.toJson(mapOf("challenge" to challenge, "chain" to List(2) { certificate })))
        }

        assertEquals(HttpStatusCode.ServiceUnavailable, response.status)
        assertEquals("unavailable", json.fromJson(response.bodyAsText(), Map::class.java)["error"])
    }

    @Test
    fun oversizedHttpRequestIsRejected() = testApplication {
        application {
            attestationApi(InMemoryChallengeStore(), EvidenceVerifier { _, _, _ -> error("called") })
        }
        val response = client.post("/verify") {
            contentType(ContentType.Application.Json)
            setBody("x".repeat(769 * 1024))
        }
        assertEquals(HttpStatusCode.PayloadTooLarge, response.status)
    }

    private fun identity(
        packageName: String = "io.github.rootect.demo",
        version: Long = 2,
        signer: ByteArray = this.signer,
    ) = AttestationApplicationId(
        setOf(AttestationPackageInfo(packageName, BigInteger.valueOf(version))),
        setOf(ByteString.copyFrom(signer)),
    )
}
