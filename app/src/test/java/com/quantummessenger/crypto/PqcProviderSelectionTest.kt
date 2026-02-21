package com.quantummessenger.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class PqcProviderSelectionTest {

    @Test
    fun `uses native provider when available`() {
        val provider = object : PqcKemProvider {
            override fun isAvailable(): Boolean = true
            override fun deriveSharedSecret(): ByteArray = ByteArray(32)
        }

        val selected = selectPqcProvider(
            allowLocalTestingFallback = true,
            nativeProviderFactory = { provider }
        )

        assertEquals(PqcProviderMode.NATIVE_LIBOQS, selected.mode)
        assertEquals(provider, selected.provider)
    }

    @Test
    fun `uses fallback provider when native is unavailable and fallback enabled`() {
        val selected = selectPqcProvider(
            allowLocalTestingFallback = true,
            nativeProviderFactory = {
                object : PqcKemProvider {
                    override fun isAvailable(): Boolean = false
                    override fun deriveSharedSecret(): ByteArray = throw PqcUnavailableException("missing")
                }
            }
        )

        assertEquals(PqcProviderMode.LOCAL_TESTING_FALLBACK, selected.mode)
        assertNotNull(selected.provider)
    }

    @Test
    fun `reports unavailable when native missing and fallback disabled`() {
        val selected = selectPqcProvider(
            allowLocalTestingFallback = false,
            nativeProviderFactory = {
                object : PqcKemProvider {
                    override fun isAvailable(): Boolean = false
                    override fun deriveSharedSecret(): ByteArray = throw PqcUnavailableException("missing")
                }
            }
        )

        assertEquals(PqcProviderMode.UNAVAILABLE, selected.mode)
        assertNull(selected.provider)
    }

    @Test(expected = PqcUnavailableException::class)
    fun `missing native bridge provider fails closed with detail`() {
        val provider = MissingNativeBridgePqcProvider("missing ABI arm64-v8a")

        assertEquals(false, provider.isAvailable())
        provider.deriveSharedSecret()
    }

}
