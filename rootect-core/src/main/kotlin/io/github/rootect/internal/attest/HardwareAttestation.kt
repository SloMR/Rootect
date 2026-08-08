package io.github.rootect.internal.attest

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.github.rootect.signal.Signal
import io.github.rootect.signal.SignalId
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate

// Asks the device's secure hardware to sign a statement about its own boot state. Unlike a
// system property, which `resetprop` rewrites, spoofing this means attacking the hardware.
internal object HardwareAttestation {

    // Google's key attestation extension.
    private const val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"

    // KeyDescription field positions.
    private const val IDX_SECURITY_LEVEL = 1
    private const val IDX_CHALLENGE = 4
    private const val IDX_TEE_ENFORCED = 7

    // AuthorizationList tag for rootOfTrust.
    private const val TAG_ROOT_OF_TRUST = 704L

    // RootOfTrust field positions.
    private const val IDX_DEVICE_LOCKED = 1
    private const val IDX_BOOT_STATE = 2

    private const val SECURITY_LEVEL_SOFTWARE = 0
    private const val BOOT_STATE_VERIFIED = 0

    /** What the hardware said, or null if it would not say anything. */
    data class Result(
        val securityLevel: Int,
        val deviceLocked: Boolean,
        val verifiedBootState: Int,
        val challenge: ByteArray = ByteArray(0),
    ) {
        val isSoftwareOnly: Boolean get() = securityLevel == SECURITY_LEVEL_SOFTWARE
        val isBootVerified: Boolean get() = verifiedBootState == BOOT_STATE_VERIFIED
    }

    /** Generates a throwaway attested key and reads the statement out of its certificate. */
    fun attest(): Result? {
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val chain = chainFor(challenge) ?: return null
        val leaf = chain.firstOrNull() ?: return null

        val parsed = parse(leaf) ?: return null

        // The certificate must answer *our* challenge. Without this a chain captured once
        // could be replayed forever.
        return if (parsed.challenge.contentEquals(challenge)) parsed else null
    }

    /**
     * The raw certificate chain, for verification somewhere the attacker cannot reach.
     * On-device parsing is only as trustworthy as the process doing it.
     */
    fun chainFor(challenge: ByteArray): List<X509Certificate>? {
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

    /** Pulls the security level and root of trust out of the attestation extension. */
    private fun parse(cert: X509Certificate): Result? {
        val raw = cert.getExtensionValue(ATTESTATION_OID) ?: return null

        // The extension value is an OCTET STRING wrapping the real KeyDescription.
        val inner = Der(raw).next()?.reader()?.next() ?: return null
        val fields = inner.reader().all()
        if (fields.size <= IDX_TEE_ENFORCED) return null

        val securityLevel = fields[IDX_SECURITY_LEVEL].asInt()
        val challenge = fields[IDX_CHALLENGE].bytes()

        val rootOfTrust = fields[IDX_TEE_ENFORCED].reader().find(TAG_ROOT_OF_TRUST)
            ?.reader()?.next()?.reader()?.all()
            ?: return Result(securityLevel, true, BOOT_STATE_VERIFIED, challenge)

        if (rootOfTrust.size <= IDX_BOOT_STATE) return null

        return Result(
            securityLevel = securityLevel,
            deviceLocked = rootOfTrust[IDX_DEVICE_LOCKED].asBoolean(),
            verifiedBootState = rootOfTrust[IDX_BOOT_STATE].asInt(),
            challenge = challenge,
        )
    }

    /**
     * Turns a hardware statement into signals. [propertiesSayLocked] is what the system
     * properties claimed, so hardware disagreeing with them can be reported.
     */
    fun signals(result: Result, propertiesSayLocked: Boolean): List<Signal> = buildList {
        if (result.isSoftwareOnly) add(Signal(SignalId.ATTESTATION_SOFTWARE_ONLY))

        if (!result.deviceLocked || !result.isBootVerified) {
            add(Signal(SignalId.ATTESTATION_BOOT_UNVERIFIED))

            // The properties claim a locked, verified device while the hardware says
            // otherwise — something is actively rewriting them.
            if (propertiesSayLocked) add(Signal(SignalId.ATTESTATION_CONTRADICTS_PROPERTIES))
        }
    }
}
