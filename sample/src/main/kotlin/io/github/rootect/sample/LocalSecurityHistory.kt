package io.github.rootect.sample

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal data class SecurityHistory(
    val rootDetected: Boolean = false,
    val attestationRejected: Boolean = false,
    // false = a stored record exists but could not be read or decrypted.
    val readable: Boolean = true,
    // true = an observed event could not be durably written to disk.
    val persistenceFailed: Boolean = false,
) {
    val hasEvents: Boolean
        get() = rootDetected || attestationRejected
}

/**
 * Encrypted local tripwire. Diagnostic only — the backend stays authoritative, and a hooked
 * process can erase or forge this. It never makes an access decision.
 */
internal object LocalSecurityHistory {

    // Events seen this session but not yet on disk, and whether the last write failed.
    private var pendingRoot = false
    private var pendingRejection = false
    private var persistenceFailed = false

    @Synchronized
    fun read(context: Context): SecurityHistory {
        val stored = readStored(context)
        return stored.copy(
            rootDetected = stored.rootDetected || pendingRoot,
            attestationRejected = stored.attestationRejected || pendingRejection,
            persistenceFailed = persistenceFailed,
        )
    }

    @Synchronized
    fun rememberRootDetection(context: Context) {
        pendingRoot = true
        persist(context)
    }

    @Synchronized
    fun rememberAttestationRejection(context: Context) {
        pendingRejection = true
        persist(context)
    }

    private fun persist(context: Context) {
        val stored = readStored(context)
        // Don't overwrite an unreadable record — that would erase the tampering it should catch.
        if (!stored.readable) {
            persistenceFailed = true
            return
        }
        val flags =
            (if (stored.rootDetected || pendingRoot) ROOT_DETECTED else 0) or
                (if (stored.attestationRejected || pendingRejection) REJECTED else 0)
        if (runCatching { write(context, flags) }.getOrDefault(false)) {
            // Durably saved: clear pending + failure only here, so failure clears after a real retry.
            pendingRoot = false
            pendingRejection = false
            persistenceFailed = false
        } else {
            persistenceFailed = true
        }
    }

    // Whole read guarded, including the preference lookup: any failure means "unreadable", not a crash.
    private fun readStored(context: Context): SecurityHistory = runCatching {
        val stored = preferences(context).getString(RECORD, null)
            ?: return@runCatching SecurityHistory()
        val parts = stored.split('.', limit = 2)
        require(parts.size == 2)
        val cipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, decode(parts[0])))
            updateAAD(AAD)
        }
        val clear = cipher.doFinal(decode(parts[1]))
        require(clear.size == 1)
        val flags = clear[0].toInt() and 0xff
        require((flags and ALL_EVENTS.inv()) == 0)
        SecurityHistory((flags and ROOT_DETECTED) != 0, (flags and REJECTED) != 0)
    }.getOrElse { SecurityHistory(readable = false) }

    // Returns commit()'s disk result — false even if the in-memory value already changed.
    private fun write(context: Context, flags: Int): Boolean {
        val cipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, key())
            updateAAD(AAD)
        }
        val value = "${encode(cipher.iv)}.${encode(cipher.doFinal(byteArrayOf(flags.toByte())))}"
        return preferences(context).edit().putString(RECORD, value).commit()
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).run {
            init(
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build(),
            )
            generateKey()
        }
    }

    private fun preferences(context: Context) =
        context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    private fun encode(value: ByteArray) = Base64.encodeToString(value, Base64.NO_WRAP)
    private fun decode(value: String) = Base64.decode(value, Base64.NO_WRAP)

    private const val ROOT_DETECTED = 1
    private const val REJECTED = 2
    private const val ALL_EVENTS = ROOT_DETECTED or REJECTED
    private const val PREFERENCES = "rootect_history"
    private const val RECORD = "record"
    private const val KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "io.github.rootect.sample.history.v1"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private val AAD = KEY_ALIAS.toByteArray()
}
