package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.asCoroutineDispatcher
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

object ProxyDispatcher {
    @Volatile var context: android.content.Context? = null

    private val cpuCores = Runtime.getRuntime().availableProcessors().coerceIn(2, 16)
    private val corePoolSize = (cpuCores * 2).coerceIn(4, 16)
    private val maxPoolSize = (cpuCores * 4).coerceIn(8, 32)
    private val threadId = AtomicInteger(1)

    val io = java.util.concurrent.ThreadPoolExecutor(
        corePoolSize,
        maxPoolSize,
        30L, java.util.concurrent.TimeUnit.SECONDS,
        java.util.concurrent.LinkedBlockingQueue<Runnable>(256),
        { r ->
            Thread(r, "PinkProxyWorker-${threadId.getAndIncrement()}").apply { 
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
        runCatching { android.util.Log.e("ProxyDispatcher", "Uncaught coroutine exception", throwable) }
            .onFailure { throwable.printStackTrace() }
    }

    val mainScope = kotlinx.coroutines.CoroutineScope(io + kotlinx.coroutines.SupervisorJob() + globalHandler)
}
