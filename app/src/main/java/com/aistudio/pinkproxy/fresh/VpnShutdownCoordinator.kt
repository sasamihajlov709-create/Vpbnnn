package com.aistudio.pinkproxy.fresh

import android.content.Context
import android.util.Log
import kotlinx.coroutines.*
import java.io.Closeable
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean

object VpnShutdownCoordinator {
        private val isShuttingDown = AtomicBoolean(false)
    private val cleanupTasks = ConcurrentLinkedQueue<() -> Unit>()

    fun registerCleanup(task: () -> Unit) {
        cleanupTasks.add(task)
    }

    fun shutdownAsync(
        context: Context?,
        onBeforeAsync: () -> Unit = {},
        timeoutMs: Long = 2500L,
        onComplete: () -> Unit = {}
    ): Job {
        onBeforeAsync()
        return (VpnSessionManager.currentSession?.controlPlaneScope ?: ProxyDispatcher.globalScope).launch {
            try {
                withTimeout(timeoutMs) {
                    executeCleanup(context)
                }
            } catch (e: TimeoutCancellationException) {
                Log.w("ShutdownCoordinator", "Async shutdown timed out after ${timeoutMs}ms, forcing remaining resources close")
                forceDrainResources()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e("ShutdownCoordinator", "Error during shutdown: ${e.message}", e)
            } finally {
                onComplete()
            }
        }
    }

    private fun executeCleanup(context: Context?) {
        while (cleanupTasks.isNotEmpty()) {
            val task = cleanupTasks.poll() ?: break
            try {
                task.invoke()
            } catch (e: Exception) {
                Log.v("ShutdownCoordinator", "Cleanup task warning: ${e.message}")
            }
        }

        context?.let { ctx ->
            try {
                val appCtx = ctx.applicationContext
                DnsCacheManager.save(appCtx)
                DpiStorage.saveProfileScores(appCtx, NetworkProfileManager.currentProfile.value.id)
            } catch (e: Exception) {
                Log.v("ShutdownCoordinator", "Storage flush warning: ${e.message}")
            }
        }
    }

    private fun forceDrainResources() {
        while (cleanupTasks.isNotEmpty()) {
            val task = cleanupTasks.poll() ?: break
            try { task.invoke() } catch (_: Exception) {}
        }
    }

    fun safeClose(closeable: Closeable?) {
        try {
            closeable?.close()
        } catch (e: Exception) {
            Log.v("ShutdownCoordinator", "Safe close error: ${e.message}")
        }
    }
}
