package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.asCoroutineDispatcher
import java.util.concurrent.Executors

object ProxyDispatcher {
    @Volatile var context: android.content.Context? = null

    private val coreCount = Runtime.getRuntime().availableProcessors()
    private val poolSize = (coreCount * 4).coerceIn(16, 64)
    val io = Executors.newFixedThreadPool(poolSize) { r ->
        Thread(r, "PinkProxyWorker").apply { 
            isDaemon = true
            priority = Thread.MAX_PRIORITY - 1
        }
    }.asCoroutineDispatcher()
    
    val scheduler = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "PinkProxyScheduler").apply { isDaemon = true }
    }.asCoroutineDispatcher()
}
