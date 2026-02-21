package com.quantummessenger

import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.quantummessenger.crypto.HybridSessionManager
import com.quantummessenger.crypto.LiboqsMlKemProvider
import com.quantummessenger.crypto.MissingNativeBridgePqcProvider
import com.quantummessenger.crypto.PqcProviderMode
import com.quantummessenger.crypto.PqcUnavailableException
import com.quantummessenger.crypto.RatchetState
import com.quantummessenger.crypto.SecureMessageRatchet
import com.quantummessenger.crypto.X25519KeyAgreementProvider
import com.quantummessenger.crypto.selectPqcProvider
import java.io.File

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        setContentView(R.layout.activity_main)

        val statusView = findViewById<TextView>(R.id.statusView)
        val rotateKeysButton = findViewById<Button>(R.id.rotateKeysButton)

        val isDebugBuild = (applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
        val nativeLibDir = applicationInfo.nativeLibraryDir
        val nativeBridgePackaged = nativeLibDir != null &&
            File(nativeLibDir, System.mapLibraryName("oqsbridge")).exists()

        val preferredAbi = Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown"
        val providerSelection = selectPqcProvider(
            allowLocalTestingFallback = isDebugBuild,
            nativeProviderFactory = {
                if (nativeBridgePackaged) {
                    LiboqsMlKemProvider()
                } else {
                    MissingNativeBridgePqcProvider(
                        detail = "liboqs JNI bridge (oqsbridge) binary is not packaged for ABI=$preferredAbi"
                    )
                }
            }
        )
        val sessionManager = providerSelection.provider?.let {
            HybridSessionManager(
                classicProvider = X25519KeyAgreementProvider(),
                pqcProvider = it
            )
        }

        when (providerSelection.mode) {
            PqcProviderMode.NATIVE_LIBOQS -> {
                statusView.text = getString(R.string.security_status)
            }
            PqcProviderMode.LOCAL_TESTING_FALLBACK -> {
                statusView.text = getString(R.string.pqc_debug_fallback)
            }
            PqcProviderMode.UNAVAILABLE -> {
                statusView.text = getString(R.string.pqc_missing_with_abi, preferredAbi)
                rotateKeysButton.isEnabled = false
                return
            }
        }

        rotateKeysButton.setOnClickListener {
            val safeSessionManager = sessionManager ?: return@setOnClickListener
            runCatching {
                val session = safeSessionManager.rotateSessionSecrets()

                val senderRatchet = SecureMessageRatchet(
                    RatchetState(epoch = session.epoch, chainKey = session.sendingChainKey, messageNumber = 0)
                )
                val receiverRatchet = SecureMessageRatchet(
                    RatchetState(epoch = session.epoch, chainKey = session.sendingChainKey.copyOf(), messageNumber = 0)
                )

                val aad = "epoch:${session.epoch}".toByteArray()
                val encrypted = senderRatchet.encrypt("PQC+PFS OK".toByteArray(), aad)
                val decrypted = receiverRatchet.decrypt(encrypted)

                val statusStringRes = when (providerSelection.mode) {
                    PqcProviderMode.NATIVE_LIBOQS -> R.string.session_rotated
                    PqcProviderMode.LOCAL_TESTING_FALLBACK -> R.string.session_rotated_debug_fallback
                    PqcProviderMode.UNAVAILABLE -> R.string.session_rotated
                }

                statusView.text = getString(
                    statusStringRes,
                    session.epoch,
                    session.keyId.take(16),
                    String(decrypted)
                )
            }.onFailure { error ->
                if (error is PqcUnavailableException || error.cause is UnsatisfiedLinkError) {
                    statusView.text = getString(R.string.pqc_runtime_unavailable)
                    rotateKeysButton.isEnabled = false
                } else {
                    statusView.text = getString(R.string.session_rotate_failed, error.message ?: "unknown")
                }
            }
        }
    }
}
