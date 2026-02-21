package com.quantummessenger

import android.os.Bundle
import android.view.WindowManager
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.quantummessenger.crypto.HybridSessionManager
import com.quantummessenger.crypto.LiboqsMlKemProvider
import com.quantummessenger.crypto.PqcUnavailableException
import com.quantummessenger.crypto.RatchetState
import com.quantummessenger.crypto.SecureMessageRatchet
import com.quantummessenger.crypto.X25519KeyAgreementProvider

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

        val sessionManager = HybridSessionManager(
            classicProvider = X25519KeyAgreementProvider(),
            pqcProvider = LiboqsMlKemProvider()
        )

        if (!sessionManager.canEstablishHybridSession()) {
            statusView.text = getString(R.string.pqc_missing)
            rotateKeysButton.isEnabled = false
            return
        }

        rotateKeysButton.setOnClickListener {
            runCatching {
                val session = sessionManager.rotateSessionSecrets()

                val senderRatchet = SecureMessageRatchet(
                    RatchetState(epoch = session.epoch, chainKey = session.sendingChainKey, messageNumber = 0)
                )
                val receiverRatchet = SecureMessageRatchet(
                    RatchetState(epoch = session.epoch, chainKey = session.sendingChainKey.copyOf(), messageNumber = 0)
                )

                val aad = "epoch:${session.epoch}".toByteArray()
                val encrypted = senderRatchet.encrypt("PQC+PFS OK".toByteArray(), aad)
                val decrypted = receiverRatchet.decrypt(encrypted)

                statusView.text = getString(
                    R.string.session_rotated,
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
