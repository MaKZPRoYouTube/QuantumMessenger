package com.quantummessenger.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HybridSessionManagerTest {

    @Test
    fun `rotation increments epoch and derives fixed-size keys`() {
        val manager = HybridSessionManager(
            classicProvider = X25519KeyAgreementProvider(),
            pqcProvider = LocalTestingPqcProvider()
        )

        val first = manager.rotateSessionSecrets()
        val second = manager.rotateSessionSecrets()

        assertEquals(1, first.epoch)
        assertEquals(2, second.epoch)
        assertEquals(32, first.rootKey.size)
        assertEquals(32, first.sendingChainKey.size)
        assertEquals(32, first.receivingChainKey.size)
        assertFalse(first.keyId == second.keyId)
    }

    @Test(expected = IllegalStateException::class)
    fun `rotation fails closed when pqc unavailable`() {
        val unavailableProvider = object : PqcKemProvider {
            override fun isAvailable(): Boolean = false
            override fun deriveSharedSecret(): ByteArray = throw PqcUnavailableException("missing")
        }

        val manager = HybridSessionManager(
            classicProvider = X25519KeyAgreementProvider(),
            pqcProvider = unavailableProvider
        )

        manager.rotateSessionSecrets()
    }

    @Test
    fun `ratchet encrypt decrypt roundtrip works`() {
        val chainKey = ByteArray(32) { it.toByte() }
        val sender = SecureMessageRatchet(RatchetState(epoch = 1, chainKey = chainKey, messageNumber = 0))
        val receiver = SecureMessageRatchet(RatchetState(epoch = 1, chainKey = chainKey.copyOf(), messageNumber = 0))

        val aad = "hdr".toByteArray()
        val msg = "hello".toByteArray()
        val encrypted = sender.encrypt(msg, aad)
        val decrypted = receiver.decrypt(encrypted)

        assertTrue(decrypted.contentEquals(msg))
    }
}
