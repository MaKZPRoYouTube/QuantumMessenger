package com.quantummessenger.crypto

import java.security.SecureRandom

interface ClassicKeyAgreementProvider {
    fun deriveSharedSecret(): ByteArray
}

interface PqcKemProvider {
    fun deriveSharedSecret(): ByteArray
}

class X25519KeyAgreementProvider : ClassicKeyAgreementProvider {
    override fun deriveSharedSecret(): ByteArray {
        // Production: replace with full X25519 ECDH from peer static + ephemeral keys.
        return ByteArray(32).also(SecureRandom()::nextBytes)
    }
}

class LiboqsMlKemProvider : PqcKemProvider {
    override fun deriveSharedSecret(): ByteArray {
        // This class is designed for JNI bridge with liboqs ML-KEM (Kyber).
        // Implementation contract: call native function that returns KEM shared secret.
        return nativeDeriveMlKemSharedSecret()
    }

    private fun nativeDeriveMlKemSharedSecret(): ByteArray {
        return try {
            System.loadLibrary("oqsbridge")
            oqsMlKemSharedSecret()
        } catch (_: UnsatisfiedLinkError) {
            // Hard fail-closed strategy for release builds: do not silently downgrade.
            throw IllegalStateException(
                "liboqs bridge is missing. Bundle oqsbridge JNI library to enable PQC."
            )
        }
    }

    private external fun oqsMlKemSharedSecret(): ByteArray
}
