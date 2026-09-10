package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancelChildren
import java.util.concurrent.Executors

/**
 * Isolated Thread Pools and Coroutine Dispatchers.
 * Replaces shared caller-runs starvation risks with dedicated bounded pools:
 * - TCP Egress Workers
 * - UDP Relay Workers
 * - DNS Query Resolvers
 * - Background Control Plane / Telemetry
 */
object ProxyDispatcher {
    @Volatile var context: android.content.Context? = null

    // Bounded dispatchers derived from Dispatchers.IO to prevent excessive thread creation
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    val io = Dispatchers.IO.limitedParallelism(16)
    
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    val tcpEgress = Dispatchers.IO.limitedParallelism(32)
    
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    val udpRelay = Dispatchers.IO.limitedParallelism(24)
    
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    val dnsResolver = Dispatchers.IO.limitedParallelism(8)

    val scheduler = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "PinkProxyScheduler").apply { isDaemon = true }
    }.asCoroutineDispatcher()

    val globalHandler = CoroutineExceptionHandler { _, throwable ->
        runCatching { android.util.Log.e("ProxyDispatcher", "Uncaught coroutine exception", throwable) }
            .onFailure { throwable.printStackTrace() }
    }

    val globalScope = CoroutineScope(Dispatchers.IO + SupervisorJob() + globalHandler)

    fun cancelAllBackgroundJobs() {
        globalScope.coroutineContext[kotlinx.coroutines.Job]?.cancelChildren()
    }
}
