package io.github.rootect

import io.github.rootect.internal.attest.HardwareAttestation

/**
 * Hardware-signed evidence, for checking on your own server rather than on the device.
 * Needs no Google Play.
 */
public object RootectAttestation {

    /**
     * Certificate chain answering a fresh 32-byte server [challenge], DER-encoded, leaf first.
     * Null means the input was invalid or the device would not attest.
     */
    @JvmStatic
    public fun chain(challenge: ByteArray): List<ByteArray>? =
        HardwareAttestation.chainFor(challenge)?.map { it.encoded }
}
