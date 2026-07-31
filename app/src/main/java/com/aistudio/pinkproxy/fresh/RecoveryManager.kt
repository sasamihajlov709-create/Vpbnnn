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
    private var lastRestartTime = 0L
    private var restartCooldown = 60000L
    private var recoveryEscalation = 0
    private var healthCheckJob: Job? = null
    private var stallMonitorJob: Job? = null

    fun startHealthCheck(scope: CoroutineScope) {
        healthCheckJob?.cancel()
        healthCheckJob = scope.launch(ProxyDispatcher.io) {
            var lastCoolDown = System.currentTimeMillis()
            
            while (isActive) {
                try {
                    // Adaptive delay: 60s if active, 120s if idle
                    val activeConns = ProxyStats.activeConnections.value
                    val delayMs = if (activeConns > 0) 60000L else 120000L
                    delay(delayMs)
                    
                    val now = System.currentTimeMillis()
                    
                    // Strategy Cooling: Periodically try to reduce escalation if things are stable
                    if (now - lastCoolDown > 600000) { // Every 10 minutes
                        val rate = ProxyStats.getSuccessRate()
                        if (recoveryEscalation > 0 && rate > 80) {
                            val reduction = if (rate > 95) 2 else 1
                            recoveryEscalation = (recoveryEscalation - reduction).coerceAtLeast(0)
                            Log.i("RecoveryManager", "Strategy cooling: Escalation reduced by $reduction to $recoveryEscalation")
                            if (recoveryEscalation == 0) BypassConfig.setPanicMode(false)
                        }
                        lastCoolDown = now
                    }
                    
                    if (activeConns > 0) {
                        if (ProxyStats.censorshipIntensity.value > 90 && ProxyStats.successRate.value < 25) {
                            handleEvent(RecoveryEvent.TUNNEL_STALL, "Critical success rate drop during active session")
                        }
                        
                        // Monitor RTT for suspicious spikes
                        val currentRtt = ProxyStats.lastLatency.value
                        if (currentRtt > 1500) {
                            handleEvent(RecoveryEvent.HIGH_RTT, "Suspicious latency spike: $currentRtt ms")
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
                delay(5000)
                val currentBytes = ProxyStats.bytesTransferred.value
                val activeConns = ProxyStats.activeConnections.value
                
                if (activeConns > 0 && currentBytes == lastBytes) {
                    stallCounter++
                    if (stallCounter >= 3) { // 15 seconds of no traffic with active conns
                        handleEvent(RecoveryEvent.TUNNEL_STALL, "No traffic for 15s with $activeConns active connections")
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
                            BypassStrategy.SNI_SPLIT, 
                            BypassStrategy.TCP_REORDER_DESYNC, 
                            BypassStrategy.OOB_DESYNC,
                            BypassStrategy.TCP_SEGMENT_DESYNC,
                            BypassStrategy.TCP_DATA_DESYNC_OVERLAP,
                            BypassStrategy.TCP_REVERSE_FRAG
                        )
                        BypassConfig.setGlobalStrategy(candidates.random())
                        triggerPanic("Active TCP Reset DPI detected")
                    }
                    DpiType.TLS_SNI_BLOCK -> {
                        val candidates = listOf(
                            BypassStrategy.SNI_SPLIT, 
                            BypassStrategy.TLS_CLIENT_HELLO_CHOP, 
                            BypassStrategy.TLS_REC_SPLIT,
                            BypassStrategy.BYEBYEDPI_HYBRID,
                            BypassStrategy.BYEBYEDPI_EXTREME,
                            BypassStrategy.ZAPRET_EXTREME,
                            BypassStrategy.TCP_REVERSE_FRAG
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
                        if (recoveryEscalation >= 2) triggerPanic("DPI Timeout Escalation")
                    }
                    DpiType.UDP_BLOCK -> {
                        val candidates = listOf(
                            BypassStrategy.UDP_QUIC_SMART_SHADOW,
                            BypassStrategy.UDP_DNS_REORDER_HYBRID,
                            BypassStrategy.UDP_SKEW_REVERSE,
                            BypassStrategy.QUIC_INITIAL_FRAGMENTATION
                        )
                        BypassConfig.setGlobalStrategy(candidates.random())
                    }
                    else -> {
                        BypassConfig.rotateGlobalStrategy()
                    }
                }
                recoveryEscalation = (recoveryEscalation + 1).coerceAtMost(3)
                // Schedule an active probe to find better strategy soon
                PinkVpnService.instance?.getServiceScope()?.launch {
                    delay(3000)
                    ServiceChecker.runActiveProbing(null)
                }
            }
            RecoveryEvent.DNS_FAILURE -> {
                Log.e("RecoveryManager", "Critical DNS failure detected. Escalation: $recoveryEscalation")
                if (recoveryEscalation < 2) {
                    RobustResolver.clearCache()
                    DnsOptimizer.forceRefresh()
                    recoveryEscalation++
                } else {
                    RobustResolver.clearCache()
                    DnsOptimizer.forceRefresh()
                    triggerPanic("Repeated DNS failures")
                    requestServiceRestart("Persistent DNS failures")
                }
            }
            RecoveryEvent.PROXY_UNREACHABLE -> {
                recoveryEscalation = 3
                triggerPanic("Proxy unreachable")
                requestServiceRestart("Proxy crash or unreachable")
            }
            RecoveryEvent.TUNNEL_STALL, RecoveryEvent.TCP_STALL, RecoveryEvent.SSL_STALL, RecoveryEvent.CENSORSHIP_STALL -> {
                if (recoveryEscalation < 3) {
                    BypassConfig.rotateGlobalStrategy()
                    if (recoveryEscalation > 0) {
                        val currentMtu = BypassConfig.currentMtu.value
                        if (currentMtu > 1100) {
                            val reduction = if (event == RecoveryEvent.SSL_STALL || event == RecoveryEvent.CENSORSHIP_STALL) 150 else 80
                            BypassConfig.setMtu(currentMtu - reduction)
                            ProxyStats.logRecovery("Watchdog: Reducing MTU to ${currentMtu - reduction} due to $event")
                        }
                    }
                    recoveryEscalation++
                    
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
                } else {
                    triggerPanic("Critical stall detected ($event)")
                    requestServiceRestart("Persistent stalling")
                }
            }
            RecoveryEvent.DNS_POISONED -> {
                Log.e("RecoveryManager", "DNS Poisoning detected! Switching to DoH-only mode.")
                RobustResolver.clearCache()
                RobustResolver.dnsMode = "Smart DoH"
                DnsOptimizer.forceRefresh()
                recoveryEscalation++
            }
            RecoveryEvent.MTU_EXCEEDED -> {
                val currentMtu = BypassConfig.currentMtu.value
                if (currentMtu > 1200) {
                    BypassConfig.setMtu(currentMtu - 100)
                }
            }
            RecoveryEvent.HIGH_RTT, RecoveryEvent.HANDSHAKE_FAILURE -> {
                BypassConfig.rotateGlobalStrategy()
                recoveryEscalation = (recoveryEscalation + 1).coerceAtMost(2)
            }
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
        recoveryEscalation = 0
        
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
            BypassConfig.panicOptimize()
        }
    }
}
