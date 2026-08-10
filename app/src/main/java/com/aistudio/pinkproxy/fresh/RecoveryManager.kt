package com.aistudio.pinkproxy.fresh

import android.util.Log
import kotlinx.coroutines.*

enum class RecoveryEvent {
    DNS_FAILURE,
    PROXY_UNREACHABLE,
    TUNNEL_STALL,
    HIGH_RTT,
    HANDSHAKE_FAILURE,
    DPI_DETECTED,
    TCP_STALL,
    SSL_STALL,
    CENSORSHIP_STALL,
    DNS_POISONED,
    MTU_EXCEEDED
}

object RecoveryManager {
    fun stopHealthCheck() {
        healthCheckJob?.cancel()
        healthCheckJob = null
        stallMonitorJob?.cancel()
        stallMonitorJob = null
    }

    private var lastRestartTime = 0L
    private var restartCooldown = 60000L
    private val recoveryEscalation = java.util.concurrent.atomic.AtomicInteger(0)
    private var healthCheckJob: Job? = null
    private var stallMonitorJob: Job? = null

    private val blacklistedHosts = java.util.concurrent.ConcurrentHashMap<String, Long>()
    
    fun isHostBlacklisted(host: String): Boolean {
        val expiry = blacklistedHosts[host] ?: return false
        if (System.currentTimeMillis() > expiry) {
            blacklistedHosts.remove(host)
            return false
        }
        return true
    }

    fun blacklistHost(host: String, durationMs: Long = 300000) {
        blacklistedHosts[host] = System.currentTimeMillis() + durationMs
        Log.i("RecoveryManager", "Host $host blacklisted for ${durationMs/1000}s")
    }

    fun startHealthCheck(scope: CoroutineScope) {
        healthCheckJob?.cancel()
        healthCheckJob = scope.launch(ProxyDispatcher.io) {
            var lastCoolDown = System.currentTimeMillis()
            
            while (isActive) {
                try {
                    // Adaptive delay: 60s if active, 120s if idle
                    val activeConns = ProxyStats.activeConnections.value
                    val delayMs = if (activeConns > 0) 45000L else 90000L
                    delay(delayMs)
                    
                    val now = System.currentTimeMillis()
                    
                    // Periodically clean blacklist
                    blacklistedHosts.entries.removeIf { it.value < now }
                    
                    // Strategy Cooling: Periodically try to reduce escalation if things are stable
                    if (now - lastCoolDown > 600000) { // Every 10 minutes
                        val rate = ProxyStats.successRate.value
                        val currentEsc = recoveryEscalation.get()
                        if (currentEsc > 0 && rate > 80) {
                            val reduction = if (rate > 95) 2 else 1
                            val newVal = (currentEsc - reduction).coerceAtLeast(0)
                            recoveryEscalation.set(newVal)
                            Log.i("RecoveryManager", "Strategy cooling: Escalation reduced by $reduction to $newVal")
                            if (newVal == 0) BypassConfig.setPanicMode(false)
                        }
                        lastCoolDown = now
                    }
                    
                    if (activeConns > 0) {
                        val rate = ProxyStats.successRate.value
                        if (ProxyStats.censorshipIntensity.value > 85 && rate < 30) {
                            handleEvent(RecoveryEvent.TUNNEL_STALL, "Low success rate ($rate%) with high intensity")
                        }
                        
                        // Monitor RTT for suspicious spikes
                        val currentRtt = ProxyStats.lastLatency.value
                        if (currentRtt > 2500) {
                            handleEvent(RecoveryEvent.HIGH_RTT, "Extreme latency spike: $currentRtt ms")
                        }
                    }
                    
                    if (ProxyStats.currentDpiType.value != DpiType.NONE) {
                        handleEvent(RecoveryEvent.DPI_DETECTED, "DPI: ${ProxyStats.currentDpiType.value}")
                        ProxyStats.clearDpiType()
                    }
                } catch (e: kotlinx.coroutines.CancellationException) {
                    throw e
                } catch (e: Throwable) {
                    Log.e("RecoveryManager", "Health check error", e)
                }
            }
        }

        stallMonitorJob?.cancel()
        stallMonitorJob = scope.launch(ProxyDispatcher.io) {
            var lastBytes = ProxyStats.bytesTransferred.value
            var stallCounter = 0
            
            while (isActive) {
                val rtt = BypassConfig.currentRttMs.value
                val checkInterval = if (rtt > 800) 8000L else 5000L
                delay(checkInterval)
                
                val currentBytes = ProxyStats.bytesTransferred.value
                val activeConns = ProxyStats.activeConnections.value
                
                if (activeConns > 0 && currentBytes == lastBytes) {
                    stallCounter++
                    val threshold = if (rtt > 1000) 4 else 3
                    if (stallCounter >= threshold) { 
                        handleEvent(RecoveryEvent.TUNNEL_STALL, "No traffic for ${stallCounter * checkInterval / 1000}s with $activeConns active connections")
                        stallCounter = 0
                    }
                } else {
                    stallCounter = 0
                }
                lastBytes = currentBytes
            }
        }
    }


    fun handleEvent(event: RecoveryEvent, details: String = "") {
        Log.w("RecoveryManager", "Handling event: $event ($details)")
        ProxyStats.logRecovery("Event: $event ($details)")
        
        when (event) {
            RecoveryEvent.DPI_DETECTED -> {
                val type = ProxyStats.currentDpiType.value
                when (type) {
                    DpiType.TCP_RESET -> {
                        val candidates = listOf(
                            BypassStrategy.TCP_COMBINED_NUCLEAR,
                            BypassStrategy.TCP_COMBINED_HYBRID,
                            BypassStrategy.TCP_DATA_DESYNC_OVERLAP,
                            BypassStrategy.OOB_DESYNC
                        )
                        BypassConfig.setGlobalStrategy(candidates.random())
                        triggerPanic("Active TCP Reset DPI detected")
                    }
                    DpiType.TLS_SNI_BLOCK -> {
                        val candidates = listOf(
                            BypassStrategy.TCP_COMBINED_NUCLEAR,
                            BypassStrategy.BYEBYEDPI_EXTREME,
                            BypassStrategy.ZAPRET_EXTREME,
                            BypassStrategy.SNI_SPLIT,
                            BypassStrategy.TLS_CLIENT_HELLO_CHOP
                        )
                        BypassConfig.setGlobalStrategy(candidates.random())
                    }
                    DpiType.HTTP_BLOCK -> {
                        val candidates = listOf(
                            BypassStrategy.HTTP_HOST_SPACE, 
                            BypassStrategy.HTTP_HOST_CASE_MANGLE, 
                            BypassStrategy.HTTP_HOST_TAB_MANGLE,
                            BypassStrategy.HTTP_METHOD_CASE_MANGLE,
                            BypassStrategy.HTTP_HOST_REORDER
                        )
                        BypassConfig.setGlobalStrategy(candidates.random())
                    }
                    DpiType.CONNECTION_TIMEOUT -> {
                        val candidates = listOf(BypassStrategy.TLS_REC_SPLIT, BypassStrategy.TCP_ACK_SKEW, BypassStrategy.TCP_WINDOW_SIZE_CHAOS)
                        BypassConfig.setGlobalStrategy(candidates.random())
                        if (recoveryEscalation.get() >= 2) triggerPanic("DPI Timeout Escalation")
                    }
                    DpiType.UDP_BLOCK -> {
                        val candidates = listOf(
                            BypassStrategy.UDP_COMBINED_NUCLEAR,
                            BypassStrategy.UDP_COMBINED_HYBRID,
                            BypassStrategy.UDP_QUIC_SMART_SHADOW,
                            BypassStrategy.QUIC_INITIAL_FRAGMENTATION
                        )
                        BypassConfig.setGlobalStrategy(candidates.random())
                    }
                    else -> {
                        BypassConfig.rotateGlobalStrategy()
                    }
                }
                recoveryEscalation.set((recoveryEscalation.get() + 1).coerceAtMost(3))
                // Schedule an active probe to find better strategy soon
                PinkVpnService.instance?.getServiceScope()?.launch {
                    delay(3000)
                    ServiceChecker.runActiveProbing(PinkVpnService.instance ?: ProxyDispatcher.context!!)
                }
            }
            RecoveryEvent.DNS_FAILURE, RecoveryEvent.DNS_POISONED -> {
                Log.e("RecoveryManager", "Critical DNS issue detected: $event. Escalation: ${recoveryEscalation.get()}")
                RobustResolver.clearCache()
                DnsCacheManager.clearAll()
                DnsOptimizer.forceRefresh()
                
                if (event == RecoveryEvent.DNS_POISONED) {
                    // Force the app to use nuclear/smuggling DoH immediately
                    BypassConfig.setPanicMode(true)
                    // Force the app to use nuclear/smuggling DoH immediately
                    RobustResolver.dnsMode = "Smart DoH"
                }

                if (recoveryEscalation.get() < 2) {
                    recoveryEscalation.incrementAndGet()
                } else {
                    triggerPanic("Repeated DNS issues")
                    requestServiceRestart("Persistent DNS failures or poisoning")
                }
            }
            RecoveryEvent.PROXY_UNREACHABLE -> {
                val currentEsc = recoveryEscalation.get()
                if (currentEsc < 2) {
                    recoveryEscalation.incrementAndGet()
                    Log.w("RecoveryManager", "Proxy unresponsive, attempting proxy server restart (escalation ${currentEsc + 1})")
                    PinkVpnService.instance?.restartProxyServer()
                } else {
                    recoveryEscalation.set(3)
                    triggerPanic("Proxy unreachable")
                    requestServiceRestart("Proxy crash or unreachable")
                }
            }
            RecoveryEvent.TUNNEL_STALL, RecoveryEvent.TCP_STALL, RecoveryEvent.SSL_STALL, RecoveryEvent.CENSORSHIP_STALL -> {
                val currentEsc = recoveryEscalation.get()
                if (currentEsc < 3) {
                    BypassConfig.rotateGlobalStrategy()
                    if (currentEsc > 0) {
                        val currentMtu = BypassConfig.currentMtu.value
                        if (currentMtu > 1100) {
                            val reduction = if (event == RecoveryEvent.SSL_STALL || event == RecoveryEvent.CENSORSHIP_STALL) 150 else 80
                            BypassConfig.setMtu(currentMtu - reduction)
                            ProxyStats.logRecovery("Watchdog: Reducing MTU to ${currentMtu - reduction} due to $event")
                        }
                        
                        // Dynamic TTL shifting for fake desync packets
                        val currentTtl = BypassConfig.currentTtl
                        val newTtl = when (currentTtl) {
                            3 -> 5
                            5 -> 8
                            8 -> 10
                            else -> 3
                        }
                        BypassConfig.setTtl(newTtl)
                        ProxyStats.logRecovery("Watchdog: Shifting Fake TTL to $newTtl due to $event")
                    }
                    recoveryEscalation.incrementAndGet()
                    
                    // Specific boost for SSL or Censorship stalling
                    if (event == RecoveryEvent.SSL_STALL || event == RecoveryEvent.CENSORSHIP_STALL) {
                        BypassConfig.setGlobalStrategy(listOf(
                            BypassStrategy.TLS_REC_SPLIT,
                            BypassStrategy.TLS_CLIENT_HELLO_CHOP,
                            BypassStrategy.BYEBYEDPI_EXTREME,
                            BypassStrategy.TCP_WINDOW_SHRINK,
                            BypassStrategy.TCP_TLS_SESSION_DESYNC
                        ).random())
                    }
                    
                    // Force immediate re-evaluation via active probing
                    PinkVpnService.instance?.getServiceScope()?.launch {
                        delay(2000)
                        ServiceChecker.runActiveProbing(PinkVpnService.instance ?: ProxyDispatcher.context!!)
                    }
                } else {
                    triggerPanic("Critical stall detected ($event)")
                    requestServiceRestart("Persistent stalling")
                }
            }
            RecoveryEvent.MTU_EXCEEDED -> {
                val currentMtu = BypassConfig.currentMtu.value
                if (currentMtu > 1200) {
                    BypassConfig.setMtu(currentMtu - 100)
                }
            }
            RecoveryEvent.HIGH_RTT, RecoveryEvent.HANDSHAKE_FAILURE -> {
                BypassConfig.rotateGlobalStrategy()
                recoveryEscalation.set((recoveryEscalation.get() + 1).coerceAtMost(2))
            }
        }
    }

    fun recalibrateEverything() {
        Log.w("RecoveryManager", "RECALIBRATING EVERYTHING")
        ProxyStats.logRecovery("Recalibrating system...")
        
        // Reset scores and histories
        DpiEngine.resetStrategyScoresForNetworkChange()
        DpiEngine.clearCircuitBreakers()
        DpiEngine.successHistory.clear()
        DpiEngine.failureHistory.clear()
        DpiEngine.eventHistory.clear()
        
        // Clear DNS caches
        DnsCacheManager.clearAll()
        RobustResolver.clearCache()
        DnsOptimizer.forceRefresh()
        
        // Reset escalation
        recoveryEscalation.set(0)
        BypassConfig.setPanicMode(false)
        BypassConfig.setMtu(1400) // Reset to standard
        
        // Trigger active probing to find a working strategy ASAP
        PinkVpnService.instance?.getServiceScope()?.launch {
            ServiceChecker.runActiveProbing(PinkVpnService.instance ?: ProxyDispatcher.context!!)
        }
    }

    private fun requestServiceRestart(reason: String) {
        val now = System.currentTimeMillis()
        if (now - lastRestartTime < restartCooldown) {
            Log.w("RecoveryManager", "Skipping restart: cooldown active ($reason)")
            return
        }
        
        lastRestartTime = now
        restartCooldown = (restartCooldown * 1.5).toLong().coerceAtMost(300000L)
        
        Log.e("RecoveryManager", "Requesting Service Restart: $reason")
        recoveryEscalation.set(0)
        
        val context = PinkVpnService.instance ?: return
        val intent = android.content.Intent(context, PinkVpnService::class.java).apply {
            action = "RESTART"
        }
        try {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        } catch (e: Throwable) {
            Log.e("RecoveryManager", "Failed to restart service: ${e.message}")
        }
    }

    private fun triggerPanic(reason: String) {
        if (!BypassConfig.isPanicMode) {
            Log.w("RecoveryManager", "Triggering Panic Mode: $reason")
            ProxyStats.clearCensorshipHistory()
            BypassConfig.panicOptimize()
        }
    }
}
