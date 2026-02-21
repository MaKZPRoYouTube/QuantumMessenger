package com.quantummessenger.crypto

import com.quantummessenger.data.SessionSecrets
import java.nio.ByteBuffer
import java.util.UUID

class HybridSessionManager(
    private val classicProvider: ClassicKeyAgreementProvider,
    private val pqcProvider: PqcKemProvider
) {
    private var epoch: Long = 0

    fun canEstablishHybridSession(): Boolean = pqcProvider.isAvailable()

    fun rotateSessionSecrets(): SessionSecrets {
        check(canEstablishHybridSession()) { "PQC provider unavailable. Hybrid session is mandatory." }

        val classicSecret = classicProvider.deriveSharedSecret()
        val pqcSecret = pqcProvider.deriveSharedSecret()
        val ikm = classicSecret + pqcSecret

        epoch += 1
        val keyMaterial = Hkdf.sha256(
            ikm = ikm,
            salt = ByteBuffer.allocate(8).putLong(epoch).array(),
            info = "quantum-messenger-hybrid-root".toByteArray(),
            outLen = 96
        )

        val rootKey = keyMaterial.copyOfRange(0, 32)
        val sendChain = keyMaterial.copyOfRange(32, 64)
        val recvChain = keyMaterial.copyOfRange(64, 96)

        ikm.fill(0)
        classicSecret.fill(0)
        pqcSecret.fill(0)

        return SessionSecrets(
            epoch = epoch,
            keyId = UUID.nameUUIDFromBytes(rootKey).toString(),
            rootKey = rootKey,
            sendingChainKey = sendChain,
            receivingChainKey = recvChain
        )
    }
}
