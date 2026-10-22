package io.github.rootect.internal.attest

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.github.rootect.signal.Signal
import io.github.rootect.signal.SignalId
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate

// Reads a hardware-signed boot statement. Server validation remains authoritative.
internal object HardwareAttestation {

    // Google's key attestation extension.
    private const val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"

    // KeyDescription field positions.
    private const val IDX_SECURITY_LEVEL = 1
    private const val IDX_KEYMINT_SECURITY_LEVEL = 3
    private const val IDX_CHALLENGE = 4
    private const val IDX_TEE_ENFORCED = 7

    // Universal tag numbers of the fields read below.
    private const val TAG_BOOLEAN = 1L
    private const val TAG_OCTET_STRING = 4L
    private const val TAG_ENUMERATED = 10L
    private const val TAG_SEQUENCE = 16L

    // AuthorizationList tag for rootOfTrust.
    private const val TAG_ROOT_OF_TRUST = 704L

    // RootOfTrust field positions.
    private const val IDX_DEVICE_LOCKED = 1
    private const val IDX_BOOT_STATE = 2

    private const val SECURITY_LEVEL_SOFTWARE = 0
    private const val SECURITY_LEVEL_STRONGBOX = 2
    private const val BOOT_STATE_VERIFIED = 0
    private const val BOOT_STATE_SELF_SIGNED = 1
    private const val BOOT_STATE_FAILED = 3
    private const val CHALLENGE_SIZE = 32
    private const val MAX_EXTENSION_BYTES = 64 * 1024

    /** What the attestation record said, or null if it could not be parsed. */
    data class Result(
        val securityLevel: Int,
        val deviceLocked: Boolean?,
        val verifiedBootState: Int?,
        val challenge: ByteArray = ByteArray(0),
    ) {
        val isSoftwareOnly: Boolean get() = securityLevel == SECURITY_LEVEL_SOFTWARE
        val hasRootOfTrust: Boolean get() = deviceLocked != null && verifiedBootState != null
        val isBootVerified: Boolean get() = verifiedBootState == BOOT_STATE_VERIFIED
        val isBootSelfSigned: Boolean get() = verifiedBootState == BOOT_STATE_SELF_SIGNED
    }

    /** Generates a throwaway attested key and reads the statement out of its certificate. */
    fun attest(): Result? {
        val challenge = ByteArray(CHALLENGE_SIZE).also { SecureRandom().nextBytes(it) }
        val chain = chainFor(challenge) ?: return null
        return parseChain(chain, challenge)
    }

    internal fun parseChain(chain: List<X509Certificate>, challenge: ByteArray): Result? {
        if (chain.size !in 1..8) return null
        val extensions = runCatching { chain.map { it.getExtensionValue(ATTESTATION_OID) } }
            .getOrNull() ?: return null
        return parseChainExtensions(extensions, challenge)
    }

    // Android returns leaf first. Select the extension nearest the root; a descendant
    // can contain an attacker-added extension. This does not authenticate the chain.
    internal fun parseChainExtensions(extensions: List<ByteArray?>, challenge: ByteArray): Result? {
        if (challenge.size != CHALLENGE_SIZE || extensions.size !in 1..8) return null
        val raw = extensions.lastOrNull { it != null } ?: return null
        if (raw.size > MAX_EXTENSION_BYTES) return null
        val parsed = parseExtension(raw) ?: return null
        return parsed.takeIf { it.challenge.contentEquals(challenge) }
    }

    /**
     * The raw certificate chain, for verification somewhere the attacker cannot reach.
     * On-device parsing is only as trustworthy as the process doing it.
     */
    fun chainFor(challenge: ByteArray): List<X509Certificate>? {
        if (challenge.size != CHALLENGE_SIZE) return null
        val alias = "rootect-attest-${System.nanoTime()}"
        val keyStore = runCatching {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        }.getOrNull() ?: return null

        try {
            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore",
            )
            generator.initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .build(),
            )
            generator.generateKeyPair()

            return keyStore.getCertificateChain(alias)
                ?.mapNotNull { it as? X509Certificate }
                ?.takeIf { it.isNotEmpty() }
        } catch (_: Throwable) {
            // Devices without attestation support throw rather than return, and a missing
            // answer is not evidence of anything.
            return null
        } finally {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    internal fun parseExtension(raw: ByteArray): Result? {
        // The extension value is an OCTET STRING wrapping the real KeyDescription.
        val inner = Der(raw).next()?.reader()?.next() ?: return null
        val fields = inner.reader().all()
        if (fields.size <= IDX_TEE_ENFORCED) return null
        // A field of the wrong type is a malformed record, not a value to coerce.
        if (fields[IDX_SECURITY_LEVEL].tag != TAG_ENUMERATED ||
            fields[IDX_KEYMINT_SECURITY_LEVEL].tag != TAG_ENUMERATED ||
            fields[IDX_CHALLENGE].tag != TAG_OCTET_STRING ||
            fields[IDX_TEE_ENFORCED].tag != TAG_SEQUENCE
        ) return null

        val attestationSecurityLevel = fields[IDX_SECURITY_LEVEL].asInt()
        val keyMintSecurityLevel = fields[IDX_KEYMINT_SECURITY_LEVEL].asInt()
        if (attestationSecurityLevel !in SECURITY_LEVEL_SOFTWARE..SECURITY_LEVEL_STRONGBOX ||
            keyMintSecurityLevel !in SECURITY_LEVEL_SOFTWARE..SECURITY_LEVEL_STRONGBOX
        ) return null
        val securityLevel = minOf(attestationSecurityLevel, keyMintSecurityLevel)
        val challenge = fields[IDX_CHALLENGE].bytes()

        // A software record has no trustworthy hardware rootOfTrust. Preserve that as
        // unknown so callers emit only the software-only signal.
        if (securityLevel == SECURITY_LEVEL_SOFTWARE) {
            return Result(securityLevel, null, null, challenge)
        }

        val rootOfTrust = fields[IDX_TEE_ENFORCED].reader().find(TAG_ROOT_OF_TRUST)
            ?.reader()?.next()?.reader()?.all()
            ?: return null

        if (rootOfTrust.size <= IDX_BOOT_STATE) return null
        if (rootOfTrust[IDX_DEVICE_LOCKED].tag != TAG_BOOLEAN ||
            rootOfTrust[IDX_BOOT_STATE].tag != TAG_ENUMERATED
        ) return null
        val verifiedBootState = rootOfTrust[IDX_BOOT_STATE].asInt()
        if (verifiedBootState !in BOOT_STATE_VERIFIED..BOOT_STATE_FAILED) return null

        return Result(
            securityLevel = securityLevel,
            deviceLocked = rootOfTrust[IDX_DEVICE_LOCKED].asBoolean(),
            verifiedBootState = verifiedBootState,
            challenge = challenge,
        )
    }

    /**
     * Turns a hardware statement into signals. [propertiesSayLocked] is what the system
     * properties claimed, so hardware disagreeing with them can be reported.
     */
    fun signals(result: Result, propertiesSayLocked: Boolean): List<Signal> = buildList {
        if (result.isSoftwareOnly) add(Signal(SignalId.ATTESTATION_SOFTWARE_ONLY))

        if (!result.hasRootOfTrust) return@buildList

        // SelfSigned on a locked device is an OS on a user-enrolled key.
        // Rootect cannot tell whose key it is, so it is posture rather than an unverified boot.
        if (result.deviceLocked == true && result.isBootSelfSigned) {
            add(Signal(SignalId.ATTESTATION_SELF_SIGNED_BOOT))
        } else if (result.deviceLocked == false || !result.isBootVerified) {
            add(Signal(SignalId.ATTESTATION_BOOT_UNVERIFIED))

            // The properties claim a locked, verified device while the hardware says
            // otherwise — something is actively rewriting them.
            if (propertiesSayLocked) add(Signal(SignalId.ATTESTATION_CONTRADICTS_PROPERTIES))
        }
    }
}
