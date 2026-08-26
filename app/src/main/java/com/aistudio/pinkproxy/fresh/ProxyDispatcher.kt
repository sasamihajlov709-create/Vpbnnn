package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancelChildren
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Isolated Thread Pools and Coroutine Dispatchers.
 * Replaces shared caller-runs starvation risks with dedicated pools:
 * - TCP Egress Workers
 * - UDP Relay Workers
 * - DNS Query Resolvers
 * - Background Control Plane / Telemetry
 */
object ProxyDispatcher {
    @Volatile var context: android.content.Context? = null

    private val cpuCores = Runtime.getRuntime().availableProcessors().coerceIn(2, 16)
    private val threadId = AtomicInteger(1)

    // Primary I/O & General Socket Pool
    val io = ThreadPoolExecutor(
        (cpuCores * 2).coerceIn(4, 16),
        (cpuCores * 4).coerceIn(8, 32),
        30L, TimeUnit.SECONDS,
        LinkedBlockingQueue<Runnable>(512),
        { r ->
            Thread(r, "PinkProxy-IO-${threadId.getAndIncrement()}").apply {
                isDaemon = true
                priority = Thread.NORM_PRIORITY + 1
            }
        },
        ThreadPoolExecutor.DiscardOldestPolicy()
    ).asCoroutineDispatcher()

    // Dedicated TCP Egress Pool
    val tcpEgress = ThreadPoolExecutor(
        (cpuCores * 2).coerceIn(4, 16),
        (cpuCores * 4).coerceIn(8, 32),
        30L, TimeUnit.SECONDS,
        LinkedBlockingQueue<Runnable>(512),
        { r ->
            Thread(r, "PinkProxy-TCP-${threadId.getAndIncrement()}").apply {
                isDaemon = true
                priority = Thread.NORM_PRIORITY + 1
            }
        },
        ThreadPoolExecutor.DiscardOldestPolicy()
    ).asCoroutineDispatcher()

    // Dedicated UDP Relay Pool
    val udpRelay = ThreadPoolExecutor(
        (cpuCores * 2).coerceIn(4, 12),
        (cpuCores * 3).coerceIn(6, 24),
        30L, TimeUnit.SECONDS,
        LinkedBlockingQueue<Runnable>(512),
        { r ->
            Thread(r, "PinkProxy-UDP-${threadId.getAndIncrement()}").apply {
                isDaemon = true
                priority = Thread.NORM_PRIORITY + 2 // Slightly higher priority for low latency VoIP/Datagrams
            }
        },
        ThreadPoolExecutor.DiscardOldestPolicy()
    ).asCoroutineDispatcher()

    // Dedicated DNS Resolver Pool
    val dnsResolver = ThreadPoolExecutor(
        2, 8,
        30L, TimeUnit.SECONDS,
        LinkedBlockingQueue<Runnable>(256),
        { r ->
            Thread(r, "PinkProxy-DNS-${threadId.getAndIncrement()}").apply {
                isDaemon = true
                priority = Thread.NORM_PRIORITY
            }
        },
        ThreadPoolExecutor.DiscardOldestPolicy()
    ).asCoroutineDispatcher()

    val scheduler = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "PinkProxyScheduler").apply { isDaemon = true }
    }.asCoroutineDispatcher()

    val globalHandler = CoroutineExceptionHandler { _, throwable ->
        runCatching { android.util.Log.e("ProxyDispatcher", "Uncaught coroutine exception", throwable) }
            .onFailure { throwable.printStackTrace() }
    }

    val mainScope = CoroutineScope(io + SupervisorJob() + globalHandler)

    fun cancelAllBackgroundJobs() {
        mainScope.coroutineContext[kotlinx.coroutines.Job]?.cancelChildren()
    }
}
