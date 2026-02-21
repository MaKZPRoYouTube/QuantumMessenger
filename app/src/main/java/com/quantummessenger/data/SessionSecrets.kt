package com.quantummessenger.data

data class SessionSecrets(
    val epoch: Long,
    val keyId: String,
    val rootKey: ByteArray
)
