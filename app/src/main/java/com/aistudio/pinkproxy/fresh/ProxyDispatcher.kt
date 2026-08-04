package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.asCoroutineDispatcher
import java.util.concurrent.Executors

object ProxyDispatcher {
    @Volatile var context: android.content.Context? = null

    val io = java.util.concurrent.ThreadPoolExecutor(
        16, // Core threads always kept alive
        128, // Hard ceiling to prevent thread explosion under peak traffic
        60L, java.util.concurrent.TimeUnit.SECONDS,
        java.util.concurrent.SynchronousQueue<Runnable>(),
        { r ->
            Thread(r, "PinkProxyWorker").apply { 
                isDaemon = true
                priority = Thread.NORM_PRIORITY + 1
            }
        },
        java.util.concurrent.ThreadPoolExecutor.CallerRunsPolicy() // Graceful backpressure/throttling when pool is completely saturated
    ).asCoroutineDispatcher()
    
    val scheduler = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "PinkProxyScheduler").apply { isDaemon = true }
    }.asCoroutineDispatcher()

    val globalHandler = kotlinx.coroutines.CoroutineExceptionHandler { _, throwable ->
        android.util.Log.e("ProxyDispatcher", "Uncaught coroutine exception", throwable)
    }

    val mainScope = kotlinx.coroutines.CoroutineScope(io + kotlinx.coroutines.SupervisorJob() + globalHandler)
}
