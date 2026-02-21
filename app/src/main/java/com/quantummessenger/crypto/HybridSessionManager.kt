package com.quantummessenger.crypto

import com.quantummessenger.data.SessionSecrets
import java.security.MessageDigest
import java.util.UUID

class HybridSessionManager(
    private val classicProvider: ClassicKeyAgreementProvider,
    private val pqcProvider: PqcKemProvider
) {
    private var epoch: Long = 0

    fun rotateSessionSecrets(): SessionSecrets {
        val classicSecret = classicProvider.deriveSharedSecret()
        val pqcSecret = pqcProvider.deriveSharedSecret()

        val rootKey = MessageDigest.getInstance("SHA-256")
            .digest(classicSecret + pqcSecret)

        epoch += 1
        return SessionSecrets(
            epoch = epoch,
            keyId = UUID.nameUUIDFromBytes(rootKey).toString(),
            rootKey = rootKey
        )
    }
}
