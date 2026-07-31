package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.asCoroutineDispatcher
import java.util.concurrent.Executors

object ProxyDispatcher {
    @Volatile var context: android.content.Context? = null

    val io = Executors.newCachedThreadPool() { r ->
        Thread(r, "PinkProxyWorker").apply { 
            isDaemon = true
            priority = Thread.MAX_PRIORITY - 1
        }
    }.asCoroutineDispatcher()
    
    val scheduler = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "PinkProxyScheduler").apply { isDaemon = true }
    }.asCoroutineDispatcher()

    val mainScope = kotlinx.coroutines.CoroutineScope(io + kotlinx.coroutines.SupervisorJob())
}
