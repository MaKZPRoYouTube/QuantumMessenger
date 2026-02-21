package com.quantummessenger.crypto

import javax.crypto.KeyAgreement
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.NamedParameterSpec
import java.util.concurrent.atomic.AtomicBoolean

interface ClassicKeyAgreementProvider {
    fun deriveSharedSecret(): ByteArray
}

interface PqcKemProvider {
    fun isAvailable(): Boolean
    fun deriveSharedSecret(): ByteArray
}

/**
 * Real X25519 key agreement implementation.
 *
 * NOTE: this demo derives a shared secret between two freshly generated ephemeral keys
 * on-device to keep the sample self-contained. In production, one side must come from
 * a remote peer's authenticated pre-key bundle.
 */
class X25519KeyAgreementProvider : ClassicKeyAgreementProvider {
    override fun deriveSharedSecret(): ByteArray {
        val kpg = KeyPairGenerator.getInstance("X25519")
        kpg.initialize(NamedParameterSpec("X25519"))

        val localEphemeral = kpg.generateKeyPair()
        val peerEphemeral = kpg.generateKeyPair()

        val localAgreement = KeyAgreement.getInstance("X25519")
        localAgreement.init(localEphemeral.private)
        localAgreement.doPhase(peerEphemeral.public, true)
        return localAgreement.generateSecret()
    }
}

class LiboqsMlKemProvider : PqcKemProvider {
    private val loaded = AtomicBoolean(false)

    override fun isAvailable(): Boolean {
        if (loaded.get()) return true
        return try {
            System.loadLibrary("oqsbridge")
            loaded.set(true)
            true
        } catch (_: UnsatisfiedLinkError) {
            false
        }
    }

    override fun deriveSharedSecret(): ByteArray {
        if (!isAvailable()) {
            throw IllegalStateException(
                "liboqs JNI bridge (oqsbridge) not available. Refusing insecure downgrade."
            )
        }
        return oqsMlKemSharedSecret()
    }

    private external fun oqsMlKemSharedSecret(): ByteArray
}

class LocalTestingPqcProvider : PqcKemProvider {
    override fun isAvailable(): Boolean = true

    override fun deriveSharedSecret(): ByteArray {
        return ByteArray(32).also(SecureRandom()::nextBytes)
    }
}
