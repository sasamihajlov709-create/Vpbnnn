package com.aistudio.pinkproxy.fresh.cronet

import android.content.Context
import android.util.Log
import com.google.android.gms.net.CronetProviderInstaller
import kotlinx.coroutines.tasks.await
import org.chromium.net.CronetEngine
import org.chromium.net.CronetProvider
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Provides an isolated instance of CronetEngine.
 * Does not mix its lifecycle with VpnService.
 * Should be initialized explicitly and closed explicitly when no longer needed.
 */
object CronetEngineProvider {
    private const val TAG = "CronetEngineProvider"

    private var engine: CronetEngine? = null
    private val mutex = Mutex()
    private var isPlayServicesAvailable = false

    suspend fun initialize(context: Context): Boolean {
        mutex.withLock {
            if (engine != null) return true

            try {
                // Install Google Play Services Cronet Provider
                CronetProviderInstaller.installProvider(context).await()
                isPlayServicesAvailable = true
                Log.i(TAG, "Play Services Cronet provider installed successfully.")
            } catch (e: Exception) {
                Log.w(TAG, "Play Services Cronet provider installation failed. Falling back to default if available.", e)
                isPlayServicesAvailable = false
            }

            try {
                var builder: CronetEngine.Builder? = null
                
                val providers = CronetProvider.getAllProviders(context)
                
                if (isPlayServicesAvailable) {
                    val playServicesProvider = providers.find { it.name == CronetProvider.PROVIDER_NAME_APP_PACKAGED || it.name == CronetProvider.PROVIDER_NAME_FALLBACK || it.isEnabled }
                    if (playServicesProvider != null) {
                         builder = playServicesProvider.createBuilder()
                    }
                }
                
                if (builder == null) {
                    builder = CronetEngine.Builder(context)
                }

                try {
                    builder.enableQuic(true)
                           .enableHttp2(true)
                           .enableBrotli(true)
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to enable QUIC/HTTP2/Brotli on Cronet Builder (likely using Java fallback)", e)
                }
                       
                // Configure specific QUIC hints if needed, e.g. for DoH endpoints
                // builder.addQuicHint("dns.google", 443, 443)
                // builder.addQuicHint("cloudflare-dns.com", 443, 443)

                engine = builder.build()
                Log.i(TAG, "CronetEngine initialized successfully. QUIC enabled: true")
                return true
            } catch (e: Exception) {
                Log.e(TAG, "Failed to initialize CronetEngine", e)
                return false
            }
        }
    }

    fun getEngine(): CronetEngine? {
        return engine
    }

    suspend fun close() {
        mutex.withLock {
            engine?.shutdown()
            engine = null
            Log.i(TAG, "CronetEngine shutdown complete.")
        }
    }
}
