package io.github.rootect

/** Optional inputs only the host app can supply. */
public class RootectConfig(
    /**
     * SHA-256 of the certificate this app should be signed with, hex, colons optional.
     * Null skips the check — Rootect cannot know your release key.
     */
    public val expectedSigningSha256: String? = null,

    /** Installers treated as trusted. Anything else yields UNTRUSTED_INSTALLER. */
    public val trustedInstallers: Set<String> = DEFAULT_TRUSTED_INSTALLERS,
) {
    public companion object {
        /** Google Play and its legacy feedback package. */
        public val DEFAULT_TRUSTED_INSTALLERS: Set<String> =
            setOf("com.android.vending", "com.google.android.feedback")
    }
}
