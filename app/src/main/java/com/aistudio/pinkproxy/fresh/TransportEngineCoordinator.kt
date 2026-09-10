package com.aistudio.pinkproxy.fresh

import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.*
import java.util.concurrent.CancellationException

class TransportEngineCoordinator {

    suspend fun start(vpnInterface: ParcelFileDescriptor, proxyPort: Int, proxySecret: String, coroutineScope: CoroutineScope, onSupervisorError: (Exception) -> Unit) {
        var dupFd: ParcelFileDescriptor? = null
        var rawFd = -1
        try {
            try { engine.Engine.touch() } catch (t: Throwable) { Log.e("TransportEngine", "tun2socks native engine missing: ${t.message}", t) }
            val key = try { engine.Key() } catch (t: Throwable) { throw Exception("Native Key init failed", t) }
            key.setProxy("socks5://$proxySecret:$proxySecret@127.0.0.1:$proxyPort")
            dupFd = vpnInterface.dup()
            rawFd = dupFd.detachFd()
            try { vpnInterface.close() } catch (ignored: Exception) {} // Close original to prevent FD leak
            key.setDevice("fd://$rawFd")
            key.setLogLevel("error")
            try { engine.Engine.insert(key) } catch (t: Throwable) { throw Exception("Native insert failed", t) }
            
            val startAck = CompletableDeferred<Unit>()
            coroutineScope.launch {
                try {
                    // Launch native engine start
                    val startJob = launch(Dispatchers.IO) {
                        try {
                            try { engine.Engine.start() } catch (t: Throwable) { throw Exception("Native start failed", t) }
                            Log.i("TransportEngine", "tun2socks stopped naturally")
                        } catch (e: Exception) {
                            if (!startAck.isCompleted) {
                                startAck.completeExceptionally(e)
                            } else {
                                Log.e("TransportEngine", "tun2socks run-time error", e)
                                onSupervisorError(e)
                            }
                        }
                    }

                    // A brief yield and check that Engine didn't immediately crash/fail on invalid FD/proxy
                    delay(80)
                    if (startJob.isActive && !startAck.isCompleted) {
                        startAck.complete(Unit)
                    }
                } catch (e: CancellationException) {
                    if (!startAck.isCompleted) startAck.completeExceptionally(e)
                    throw e
                } catch (e: Exception) {
                    if (!startAck.isCompleted) {
                        startAck.completeExceptionally(e)
                    } else {
                        Log.e("TransportEngine", "tun2socks supervisor error", e)
                        onSupervisorError(e)
                    }
                }
            }

            // Wait up to 1500ms to guarantee coroutine started and engine initialized
            withTimeout(1500L) {
                startAck.await()
            }
            Log.i("TransportEngine", "tun2socks started and verified on fd $rawFd")
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e("TransportEngine", "Failed to start tun2socks", e)
            if (rawFd >= 0) {
                try {
                    ParcelFileDescriptor.adoptFd(rawFd).close()
                } catch (closeEx: Exception) {
                    Log.v("TransportEngine", "FD adoption close error: ${closeEx.message}")
                }
            }
            try {
                dupFd?.close()
            } catch (_: Exception) {}
            throw e
        }
    }

    fun stop() {
        try {
            engine.Engine.stop()
        } catch (e: Exception) {
            Log.e("TransportEngine", "Failed to stop tun2socks: ${e.message}")
        }
    }
}
