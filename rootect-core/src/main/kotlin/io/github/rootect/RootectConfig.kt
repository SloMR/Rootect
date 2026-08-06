package io.github.rootect

/** Optional inputs only the host app can supply. */
public class RootectConfig(
    /** SHA-256 of this app's expected signing certificate, hex, colons optional. */
    public val expectedSigningSha256: String? = null,

    /** Installers treated as trusted. Anything else yields UNTRUSTED_INSTALLER. */
    public val trustedInstallers: Set<String> = DEFAULT_TRUSTED_INSTALLERS,

    /** Ask the secure hardware to attest the boot state. Off by default: it is slow. */
    public val hardwareAttestation: Boolean = false,
) {
    public companion object {
        /** Google Play and its legacy feedback package. */
        public val DEFAULT_TRUSTED_INSTALLERS: Set<String> =
            setOf("com.android.vending", "com.google.android.feedback")
    }
}
