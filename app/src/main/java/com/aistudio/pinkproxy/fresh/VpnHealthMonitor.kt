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
    private var memoryMonitorJob: Job? = null
    private var chaffJob: Job? = null
    private var trafficMonitorJob: Job? = null

    fun start(scope: CoroutineScope) {
        stop()
        startWatchdog(scope)
        startMemoryMonitor(scope)
        startTrafficMonitor(scope)
        startChaffGenerator(scope)
    }

    fun stop() {
        watchdogJob?.cancel()
        watchdogJob = null
        trafficMonitorJob?.cancel()
        trafficMonitorJob = null
        memoryMonitorJob?.cancel()
        memoryMonitorJob = null
        chaffJob?.cancel()
        chaffJob = null
    }

    private fun startWatchdog(scope: CoroutineScope) {
        watchdogJob = scope.launch {
            var lastDnsFailures = 0L
            var lastCoolDown = System.currentTimeMillis()

            while (isActive) {
                try {
                    val activeConns = ProxyStats.activeConnections.value
                    val isScreenOn = BypassConfig.isScreenOn
                    val delayMs = when {
                        !isScreenOn && activeConns == 0 -> 360000L // 6 min deep sleep when screen off and idle
                        !isScreenOn -> 180000L                     // 3 min when screen off with traffic
                        activeConns > 0 -> 90000L
                        else -> 180000L
                    }
                    delay(delayMs)

                    if (!isVpnRunning()) continue
                    
                    val now = System.currentTimeMillis()
                    if (now - lastCoolDown > 600000) { // Every 10 minutes
                        val rate = ProxyStats.successRate.value
                        if (rate > 80) {
                            val reduction = if (rate > 95) 2 else 1
                            RecoveryStateMachine.coolDownEscalation(reduction)
                            Log.i("VpnHealthMonitor", "Strategy cooling: RecoveryStateMachine escalation reduced by $reduction")
                        }
                        lastCoolDown = now
                    }

                    val dnsFailures = ProxyStats.dnsFailureCount.value

                    // Proxy liveness check
                    if (getProxyServer() == null) {
                        ProxyStats.logRecovery("Watchdog: Proxy server missing! Restarting...")
                        restartProxyServer()
                    } else if (isScreenOn && System.currentTimeMillis() % 300000 < delayMs) {
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
                            ProxyStats.logRecovery("Watchdog: Proxy server unresponsive (${e.message}). Reporting signal...")
                            RecoveryStateMachine.postSignal(RecoverySignal.ProxyUnresponsive(e.message ?: "io_error", transport = TransportType.TCP))
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            Log.e("VpnHealthMonitor", "Watchdog diagnostic error", e)
                        } finally {
                            try { socket.close() } catch (e: Exception) {}
                        }
                    }

                    if (dnsFailures > lastDnsFailures + 10) {
                        ProxyStats.logRecovery("Watchdog: High DNS failure rate ($dnsFailures). Reporting DNS failure signal...")
                        RecoveryStateMachine.postSignal(RecoverySignal.DnsFailure("bulk_failures", isPoisoned = false))
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

    private fun startTrafficMonitor(scope: CoroutineScope) {
        trafficMonitorJob = scope.launch {
            var lastBytes = ProxyStats.bytesTransferred.value
            var stallCounter = 0
            
            while (isActive && isVpnRunning()) {
                val rtt = BypassConfig.currentRttMs.value
                val checkInterval = if (rtt > 800) 8000L else 5000L
                delay(checkInterval)
                
                if (!isVpnRunning()) continue
                
                val currentBytes = ProxyStats.bytesTransferred.value
                val activeConns = ProxyStats.activeConnections.value
                
                // Monitor RTT for suspicious spikes
                val currentRtt = ProxyStats.lastLatency.value
                if (currentRtt > 2500 && activeConns > 0) {
                    RecoveryStateMachine.postSignal(RecoverySignal.ExtremeLatency(currentRtt, transport = TransportType.TCP))
                }
                
                // Check for DPI detected
                if (ProxyStats.currentDpiType.value != DpiType.NONE) {
                    RecoveryStateMachine.postSignal(RecoverySignal.DpiDetected(ProxyStats.currentDpiType.value, transport = TransportType.TCP))
                    ProxyStats.clearDpiType()
                }

                // Check for censorship stall
                val tcpRate = ProxyStats.tcpSuccessRate.value
                val udpRate = ProxyStats.udpSuccessRate.value
                
                if (activeConns > 0 && ProxyStats.censorshipIntensity.value > 85) {
                    if (tcpRate < 30) {
                        RecoveryStateMachine.postSignal(RecoverySignal.TunnelStall(15000L, activeConns, TransportType.TCP))
                    }
                    if (udpRate < 30) {
                        RecoveryStateMachine.postSignal(RecoverySignal.TunnelStall(15000L, activeConns, TransportType.UDP))
                    }
                }

                // Traffic stall check
                if (activeConns > 0 && currentBytes == lastBytes) {
                    stallCounter++
                    val threshold = if (rtt > 1000) 4 else 3
                    if (stallCounter >= threshold) { 
                        RecoveryStateMachine.postSignal(RecoverySignal.TunnelStall((stallCounter * checkInterval).toLong(), activeConns, transport = TransportType.TCP))
                        stallCounter = 0
                    }
                } else {
                    stallCounter = 0
                }
                lastBytes = currentBytes
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
                    Log.w("VpnHealthMonitor", "CRITICAL MEMORY: $percent% ($usedMB MB / $maxMB MB). Reporting to RecoveryStateMachine.")
                    RecoveryStateMachine.postSignal(RecoverySignal.MemoryPressure(percent))
                }
            }
        }
    }

    private fun startChaffGenerator(scope: CoroutineScope) {
        chaffJob = scope.launch {
            val rnd = ThreadLocalRandom.current()
            val decoys = listOf("google.com", "cloudflare.com", "microsoft.com", "wikipedia.org")
            while (isActive && isVpnRunning()) {
                val baseDelay = if (BypassConfig.isPanicMode) rnd.nextLong(15000, 30000) else rnd.nextLong(45000, 90000)
                val delayMs = if (!BypassConfig.isScreenOn) baseDelay * 3 else baseDelay
                delay(delayMs)
                if (!isVpnRunning() || !BypassConfig.isScreenOn) continue

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
