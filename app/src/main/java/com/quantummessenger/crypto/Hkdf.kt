package com.quantummessenger.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object Hkdf {
    fun sha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, outLen: Int): ByteArray {
        require(outLen > 0) { "outLen must be > 0" }
        val mac = Mac.getInstance("HmacSHA256")
        val zeroSalt = ByteArray(32)
        val realSalt = if (salt.isEmpty()) zeroSalt else salt

        mac.init(SecretKeySpec(realSalt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)

        var t = ByteArray(0)
        val okm = ByteArray(outLen)
        var generated = 0
        var counter = 1

        while (generated < outLen) {
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(t)
            mac.update(info)
            mac.update(counter.toByte())
            t = mac.doFinal()

            val toCopy = minOf(t.size, outLen - generated)
            System.arraycopy(t, 0, okm, generated, toCopy)
            generated += toCopy
            counter++
        }

        prk.fill(0)
        t.fill(0)
        return okm
    }
}
