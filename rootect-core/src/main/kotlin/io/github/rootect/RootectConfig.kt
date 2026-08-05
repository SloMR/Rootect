package io.github.rootect

/** Optional inputs only the host app can supply. */
public class RootectConfig(
    /**
     * SHA-256 of the certificate this app is expected to be signed with, hex, with or
     * without colons and in either case. Null skips the check — Rootect cannot know what
     * your release key is.
     */
    public val expectedSigningSha256: String? = null,

    /**
     * Installer packages treated as trusted. Anything else, including a sideload with no
     * installer at all, yields UNTRUSTED_INSTALLER.
     */
    public val trustedInstallers: Set<String> = DEFAULT_TRUSTED_INSTALLERS,
) {
    public companion object {
        /** Google Play and its legacy feedback package. */
        public val DEFAULT_TRUSTED_INSTALLERS: Set<String> =
            setOf("com.android.vending", "com.google.android.feedback")
    }
}
