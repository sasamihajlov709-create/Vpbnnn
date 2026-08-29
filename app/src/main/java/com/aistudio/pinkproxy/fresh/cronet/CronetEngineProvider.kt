package com.aistudio.pinkproxy.fresh.cronet

import android.content.Context
import android.util.Log
import com.google.android.gms.net.CronetProviderInstaller
import kotlinx.coroutines.tasks.await
import org.chromium.net.CronetEngine
import org.chromium.net.CronetProvider
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

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
    private var initDeferred = CompletableDeferred<Boolean>()
    
    private var executor: ExecutorService? = null

    @Synchronized
    fun getExecutor(): ExecutorService {
        if (executor == null || executor!!.isShutdown) {
            executor = Executors.newCachedThreadPool()
        }
        return executor!!
    }

    suspend fun initialize(context: Context): Boolean {
        mutex.withLock {
            if (engine != null) {
                if (!initDeferred.isCompleted) initDeferred.complete(true)
                return true
            }
            
            // Reset deferred if it was previously completed with failure or closed
            if (initDeferred.isCompleted) {
                initDeferred = CompletableDeferred()
            }

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
                
                // Strict priority: Play Services -> App Packaged -> Fallback
                if (isPlayServicesAvailable) {
                    val playServicesProvider = providers.find { it.name == CronetProvider.PROVIDER_NAME_APP_PACKAGED }
                    if (playServicesProvider != null) {
                         builder = playServicesProvider.createBuilder()
                         Log.i(TAG, "Using Play Services Cronet provider.")
                    }
                }
                
                if (builder == null) {
                    val fallbackProvider = providers.find { it.name == CronetProvider.PROVIDER_NAME_FALLBACK }
                    if (fallbackProvider != null) {
                        builder = fallbackProvider.createBuilder()
                        Log.i(TAG, "Using Cronet Fallback provider.")
                    } else {
                        builder = CronetEngine.Builder(context)
                        Log.i(TAG, "Using default Cronet Builder.")
                    }
                }

                try {
                    builder.enableQuic(true)
                           .enableHttp2(true)
                           .enableBrotli(true)
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to enable QUIC/HTTP2/Brotli on Cronet Builder (likely using Java fallback)", e)
                }
                       
                engine = builder.build()
                Log.i(TAG, "CronetEngine initialized successfully. QUIC enabled: true")
                initDeferred.complete(true)
                return true
            } catch (e: Exception) {
                Log.e(TAG, "Failed to initialize CronetEngine", e)
                initDeferred.complete(false)
                return false
            }
        }
    }

    suspend fun getEngine(): CronetEngine? {
        // Wait up to 3 seconds for initialization if it's currently pending
        if (!initDeferred.isCompleted) {
            withTimeoutOrNull(3000) {
                initDeferred.await()
            }
        }
        return engine
    }

    suspend fun close() {
        mutex.withLock {
            engine?.shutdown()
            engine = null
            if (!initDeferred.isCompleted) initDeferred.complete(false)
            initDeferred = CompletableDeferred() // Reset for next start
            
            synchronized(this) {
                executor?.shutdown()
                executor = null
            }
            
            Log.i(TAG, "CronetEngine shutdown complete.")
        }
    }
}
