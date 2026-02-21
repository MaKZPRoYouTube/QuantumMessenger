package com.quantummessenger.crypto

import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.InvalidAlgorithmParameterException
import java.security.spec.NamedParameterSpec
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.KeyAgreement

interface ClassicKeyAgreementProvider {
    fun deriveSharedSecret(): ByteArray
}

interface PqcKemProvider {
    fun isAvailable(): Boolean
    fun deriveSharedSecret(): ByteArray
}

class PqcUnavailableException(message: String, cause: Throwable? = null) : IllegalStateException(message, cause)

enum class PqcProviderMode {
    NATIVE_LIBOQS,
    LOCAL_TESTING_FALLBACK,
    UNAVAILABLE
}

data class PqcProviderSelection(
    val provider: PqcKemProvider?,
    val mode: PqcProviderMode
)

fun selectPqcProvider(
    allowLocalTestingFallback: Boolean,
    nativeProviderFactory: () -> PqcKemProvider = { LiboqsMlKemProvider() }
): PqcProviderSelection {
    val nativeProvider = nativeProviderFactory()
    if (nativeProvider.isAvailable()) {
        return PqcProviderSelection(nativeProvider, PqcProviderMode.NATIVE_LIBOQS)
    }

    if (allowLocalTestingFallback) {
        return PqcProviderSelection(LocalTestingPqcProvider(), PqcProviderMode.LOCAL_TESTING_FALLBACK)
    }

    return PqcProviderSelection(provider = null, mode = PqcProviderMode.UNAVAILABLE)
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
        try {
            kpg.initialize(NamedParameterSpec("X25519"))
        } catch (_: InvalidAlgorithmParameterException) {
            // Some Android providers reject NamedParameterSpec for X25519 but still
            // generate valid key pairs when used without explicit initialization.
        }

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
            throw PqcUnavailableException(
                "liboqs JNI bridge (oqsbridge) is unavailable. Hybrid session blocked by design."
            )
        }

        return try {
            oqsMlKemSharedSecret()
        } catch (error: UnsatisfiedLinkError) {
            loaded.set(false)
            throw PqcUnavailableException(
                "liboqs JNI bridge loaded without required symbol. Verify native packaging.",
                error
            )
        }
    }

    private external fun oqsMlKemSharedSecret(): ByteArray
}


class MissingNativeBridgePqcProvider(
    private val detail: String = "liboqs JNI bridge (oqsbridge) binary is not packaged for this ABI/build."
) : PqcKemProvider {
    override fun isAvailable(): Boolean = false

    override fun deriveSharedSecret(): ByteArray {
        throw PqcUnavailableException(detail)
    }
}

class LocalTestingPqcProvider : PqcKemProvider {
    override fun isAvailable(): Boolean = true

    override fun deriveSharedSecret(): ByteArray {
        return ByteArray(32).also(SecureRandom()::nextBytes)
    }
}
