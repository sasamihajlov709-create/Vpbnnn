package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.asCoroutineDispatcher
import java.util.concurrent.Executors

object ProxyDispatcher {
    @Volatile var context: android.content.Context? = null

    private val cpuCores = Runtime.getRuntime().availableProcessors()
    private val corePoolSize = Math.max(64, cpuCores * 8)
    private val maxPoolSize = Math.max(512, cpuCores * 32)

    val io = java.util.concurrent.ThreadPoolExecutor(
        corePoolSize,
        maxPoolSize,
        60L, java.util.concurrent.TimeUnit.SECONDS,
        java.util.concurrent.LinkedBlockingQueue<Runnable>(2048),
        { r ->
            Thread(r, "PinkProxyWorker").apply { 
                isDaemon = true
                priority = Thread.NORM_PRIORITY + 1
            }
        },
        java.util.concurrent.ThreadPoolExecutor.CallerRunsPolicy()
    ).asCoroutineDispatcher()
    
    val scheduler = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "PinkProxyScheduler").apply { isDaemon = true }
    }.asCoroutineDispatcher()

    val globalHandler = kotlinx.coroutines.CoroutineExceptionHandler { _, throwable ->
        android.util.Log.e("ProxyDispatcher", "Uncaught coroutine exception", throwable)
    }

    val mainScope = kotlinx.coroutines.CoroutineScope(io + kotlinx.coroutines.SupervisorJob() + globalHandler)
}
