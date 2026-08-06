package io.github.rootect

/**
 * Hardware-signed evidence, for checking on your own server rather than on the device.
 * Needs no Google Play.
 */
public object RootectAttestation {

    /**
     * Certificate chain answering [challenge], DER-encoded, leaf first. Issue the challenge
     * from your server and use it once. Null means the device would not attest.
     */
    @JvmStatic
    public fun chain(challenge: ByteArray): List<ByteArray>? =
        HardwareAttestation.chainFor(challenge)?.map { it.encoded }
}
