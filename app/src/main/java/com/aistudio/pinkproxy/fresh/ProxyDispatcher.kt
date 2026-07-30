package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.asCoroutineDispatcher
import java.util.concurrent.Executors

object ProxyDispatcher {
    @Volatile var context: android.content.Context? = null

    val io = Executors.newFixedThreadPool(16) { r ->
        Thread(r, "PinkProxyWorker").apply { 
            isDaemon = true
            priority = Thread.NORM_PRIORITY + 1
        }
    }.asCoroutineDispatcher()
    
    val scheduler = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "PinkProxyScheduler").apply { isDaemon = true }
    }.asCoroutineDispatcher()
}
