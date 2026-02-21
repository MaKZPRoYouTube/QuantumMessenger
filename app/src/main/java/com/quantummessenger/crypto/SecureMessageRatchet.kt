package com.quantummessenger.crypto

import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class RatchetState(
    val epoch: Long,
    val chainKey: ByteArray,
    val messageNumber: Int
)

data class EncryptedMessage(
    val nonce: ByteArray,
    val ciphertext: ByteArray,
    val aad: ByteArray,
    val messageNumber: Int
)

class SecureMessageRatchet(initialState: RatchetState) {
    private var state = initialState

    fun nextEncryptKey(): Pair<ByteArray, Int> {
        val material = Hkdf.sha256(
            ikm = state.chainKey,
            salt = longToBytes(state.epoch),
            info = "msg-key".toByteArray(),
            outLen = 64
        )

        val nextChainKey = material.copyOfRange(0, 32)
        val messageKey = material.copyOfRange(32, 64)
        val messageNumber = state.messageNumber + 1

        state.chainKey.fill(0)
        state = state.copy(chainKey = nextChainKey, messageNumber = messageNumber)
        return messageKey to messageNumber
    }

    fun encrypt(plainText: ByteArray, aad: ByteArray): EncryptedMessage {
        val (messageKey, number) = nextEncryptKey()
        val nonce = ByteArray(12).also(SecureRandom()::nextBytes)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(messageKey, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        val encrypted = cipher.doFinal(plainText)
        messageKey.fill(0)

        return EncryptedMessage(
            nonce = nonce,
            ciphertext = encrypted,
            aad = aad,
            messageNumber = number
        )
    }

    fun decrypt(message: EncryptedMessage): ByteArray {
        val (messageKey, _) = nextEncryptKey()

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(messageKey, "AES"),
            GCMParameterSpec(128, message.nonce)
        )
        cipher.updateAAD(message.aad)
        return cipher.doFinal(message.ciphertext).also { messageKey.fill(0) }
    }

    private fun longToBytes(value: Long): ByteArray {
        return ByteBuffer.allocate(8).putLong(value).array()
    }
}
