package com.aistudio.pinkproxy.fresh

import android.content.Context
import android.util.Log
import kotlinx.coroutines.*
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom

class VpnHealthMonitor(
    private val context: Context,
    private val proxyPort: Int,
    private val getProxyServer: () -> PinkProxyServer?,
    private val restartProxyServer: () -> Unit,
    private val restartVpnSession: () -> Unit,
    private val isVpnRunning: () -> Boolean,
    private val protectSocket: (Socket) -> Boolean
) {

    private var watchdogJob: Job? = null
    private var engineMonitorJob: Job? = null
    private var memoryMonitorJob: Job? = null
    private var chaffJob: Job? = null

    fun start(scope: CoroutineScope) {
        stop()
        startWatchdog(scope)
        startMemoryMonitor(scope)
        startEngineMonitor(scope)
        startChaffGenerator(scope)
    }

    fun stop() {
        watchdogJob?.cancel()
        watchdogJob = null
        engineMonitorJob?.cancel()
        engineMonitorJob = null
        memoryMonitorJob?.cancel()
        memoryMonitorJob = null
        chaffJob?.cancel()
        chaffJob = null
    }

    private fun startWatchdog(scope: CoroutineScope) {
        watchdogJob = scope.launch {
            var lastDnsFailures = 0L
            while (isActive) {
                try {
                    val activeConns = ProxyStats.activeConnections.value
                    val delayMs = if (activeConns > 0) 90000L else 180000L
                    delay(delayMs)

                    if (!isVpnRunning()) continue

                    val dnsFailures = ProxyStats.dnsFailureCount.value

                    // Proxy liveness check
                    if (getProxyServer() == null) {
                        ProxyStats.logRecovery("Watchdog: Proxy server missing! Restarting...")
                        restartProxyServer()
                    } else if (System.currentTimeMillis() % 300000 < delayMs) {
                        val socket = Socket()
                        try {
                            protectSocket(socket)
                            socket.connect(InetSocketAddress("127.0.0.1", proxyPort), 1000)
                            socket.close()

                            if (System.currentTimeMillis() % 600000 < delayMs) {
                                scope.launch {
                                    try {
                                        val health = DiagnosticManager.runFullDiagnostic()
                                        if (!health.tcpOk || !health.dnsOk) {
                                            ProxyStats.logRecovery("Health Warning: ${health.recommendation}")
                                        }
                                    } catch (e: CancellationException) {
                                        throw e
                                    } catch (e: Exception) {
                                        Log.e("VpnHealthMonitor", "Diagnostic check failed: ${e.message}")
                                    }
                                }
                            }
                        } catch (e: java.io.IOException) {
                            ProxyStats.logRecovery("Watchdog: Proxy server unresponsive (${e.message}). Restarting...")
                            restartProxyServer()
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            Log.e("VpnHealthMonitor", "Watchdog diagnostic error", e)
                        } finally {
                            try { socket.close() } catch (e: Exception) {}
                        }
                    }

                    if (dnsFailures > lastDnsFailures + 10) {
                        ProxyStats.logRecovery("Watchdog: High DNS failure rate ($dnsFailures). Clearing resolver cache...")
                        RobustResolver.clearCache()
                    }

                    lastDnsFailures = dnsFailures
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.e("VpnHealthMonitor", "Watchdog loop error", e)
                }
            }
        }
    }

    private fun startEngineMonitor(scope: CoroutineScope) {
        engineMonitorJob = scope.launch {
            while (isActive && isVpnRunning()) {
                delay(30000)
                if (isVpnRunning()) {
                    try {
                        val socket = Socket()
                        try { protectSocket(socket) } catch (e: Exception) {}
                        socket.connect(InetSocketAddress("127.0.0.1", proxyPort), 1500)
                        socket.close()
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        Log.e("VpnHealthMonitor", "Engine health check failed: ${e.message}. Triggering session recovery...")
                        ProxyStats.recordDpiEvent(DpiType.CONNECTION_TIMEOUT)
                        VpnRuntimeState.updateState(VpnLifecycleState.RECOVERING, "Engine health check failed. Restarting VPN...")
                        restartVpnSession()
                    }
                }
            }
        }
    }

    private fun startMemoryMonitor(scope: CoroutineScope) {
        memoryMonitorJob = scope.launch {
            while (isActive) {
                delay(60000)
                val rt = Runtime.getRuntime()
                val usedMB = (rt.totalMemory() - rt.freeMemory()) / 1024 / 1024
                val maxMB = rt.maxMemory() / 1024 / 1024
                val percent = (usedMB.toDouble() / maxMB * 100).toInt()

                if (percent > 85) {
                    Log.w("VpnHealthMonitor", "CRITICAL MEMORY: $percent% ($usedMB MB / $maxMB MB). Triggering cleanup.")
                    ProxyStats.logRecovery("System: High memory pressure ($percent%). Clearing caches.")
                    DnsCacheManager.clearAll()
                    UdpTransportHandler.clearBuffers()
                    ProxyStats.releaseAllPools()

                    if (percent > 92 && isVpnRunning()) {
                        Log.e("VpnHealthMonitor", "MEMORY EXHAUSTED ($percent%). Emergency session restart.")
                        ProxyStats.logRecovery("System: Memory exhausted. Emergency restart.")
                        restartVpnSession()
                    }
                }
            }
        }
    }

    private fun startChaffGenerator(scope: CoroutineScope) {
        chaffJob = scope.launch {
            val rnd = ThreadLocalRandom.current()
            val decoys = listOf("google.com", "cloudflare.com", "microsoft.com", "wikipedia.org")
            while (isActive && isVpnRunning()) {
                val delayMs = if (BypassConfig.isPanicMode) rnd.nextLong(15000, 30000) else rnd.nextLong(45000, 90000)
                delay(delayMs)
                if (!isVpnRunning()) break

                if (BypassConfig.isPanicMode || ProxyStats.censorshipIntensity.value > 60) {
                    try {
                        val decoy = decoys[rnd.nextInt(decoys.size)]
                        DnsProtocols.queryUdpDnsShadow(decoy, "1.1.1.1", context as? android.net.VpnService)
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        Log.v("VpnHealthMonitor", "Chaff packet error: ${e.message}")
                    }
                }
            }
        }
    }
}
