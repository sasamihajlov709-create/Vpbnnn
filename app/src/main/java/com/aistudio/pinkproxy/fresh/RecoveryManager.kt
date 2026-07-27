package com.aistudio.pinkproxy.fresh

import android.util.Log
import kotlinx.coroutines.*

enum class RecoveryEvent {
    DNS_FAILURE,
    PROXY_UNREACHABLE,
    TUNNEL_STALL,
    HIGH_RTT,
    HANDSHAKE_FAILURE,
    DPI_DETECTED
}

object RecoveryManager {
    private var lastRestartTime = 0L
    private var restartCooldown = 60000L
    private var recoveryEscalation = 0
    private var healthCheckJob: Job? = null

    fun startHealthCheck(scope: CoroutineScope) {
        healthCheckJob?.cancel()
        healthCheckJob = scope.launch(Dispatchers.IO) {
            var lastBytes = ProxyStats.bytesTransferred.value
            var lastCoolDown = System.currentTimeMillis()
            
            while (isActive) {
                delay(30000)
                
                val now = System.currentTimeMillis()
                val currentBytes = ProxyStats.bytesTransferred.value
                val active = ProxyStats.activeConnections.value
                
                // Strategy Cooling: Periodically try to reduce escalation if things are stable
                if (now - lastCoolDown > 300000) { // Every 5 minutes
                    val rate = ProxyStats.getSuccessRate()
                    if (recoveryEscalation > 0 && rate > 80) {
                        // Double cool-down if rate is perfect
                        val reduction = if (rate > 95) 2 else 1
                        recoveryEscalation = (recoveryEscalation - reduction).coerceAtLeast(0)
                        
                        Log.i("RecoveryManager", "Strategy cooling: Escalation reduced by $reduction to $recoveryEscalation")
                        if (recoveryEscalation == 0) BypassConfig.setPanicMode(false)
                    }
                    lastCoolDown = now
                }
                
                if (ProxyStats.censorshipIntensity.value > 90 && ProxyStats.getSuccessRate() < 30) {
                    handleEvent(RecoveryEvent.TUNNEL_STALL, "Critical success rate drop")
                }
                
                if (active > 0 && currentBytes == lastBytes && ProxyStats.censorshipIntensity.value > 50) {
                    handleEvent(RecoveryEvent.TUNNEL_STALL, "Ghosting detected: $active connections, 0 bytes in 30s")
                }
                
                lastBytes = currentBytes

                // ProxyStats is in BypassTypes.kt
                if (ProxyStats.currentDpiType.value != DpiType.NONE) {
                    handleEvent(RecoveryEvent.DPI_DETECTED, "DPI: ${ProxyStats.currentDpiType.value}")
                    ProxyStats.clearDpiType()
                }
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
                        BypassConfig.setGlobalStrategy(BypassStrategy.SNI_SPLIT)
                        triggerPanic("Active TCP Reset DPI detected")
                    }
                    DpiType.CONNECTION_TIMEOUT -> {
                        BypassConfig.setGlobalStrategy(BypassStrategy.TLS_REC_SPLIT)
                    }
                    else -> {
                        BypassConfig.rotateGlobalStrategy()
                    }
                }
                recoveryEscalation = (recoveryEscalation + 1).coerceAtMost(3)
            }
            RecoveryEvent.DNS_FAILURE -> {
                if (recoveryEscalation < 2) {
                    RobustResolver.clearCache()
                    recoveryEscalation++
                } else {
                    triggerPanic("Repeated DNS failures")
                    requestServiceRestart("Persistent DNS failures")
                }
            }
            RecoveryEvent.PROXY_UNREACHABLE -> {
                recoveryEscalation = 3
                triggerPanic("Proxy unreachable")
                requestServiceRestart("Proxy crash or unreachable")
            }
            RecoveryEvent.TUNNEL_STALL -> {
                if (recoveryEscalation < 3) {
                    BypassConfig.rotateGlobalStrategy()
                    if (recoveryEscalation > 1) {
                        val currentMtu = BypassConfig.currentMtu.value
                        if (currentMtu > 1200) {
                            BypassConfig.setMtu(currentMtu - 100)
                            ProxyStats.logRecovery("Watchdog: Reducing MTU to ${currentMtu - 100}")
                        }
                    }
                    recoveryEscalation++
                } else {
                    triggerPanic("Tunnel stall detected")
                    requestServiceRestart("Data flow stalled")
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
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            context.startForegroundService(intent)
        } else {
            context.startService(intent)
        }
    }

    private fun triggerPanic(reason: String) {
        if (!BypassConfig.isPanicMode) {
            Log.w("RecoveryManager", "Triggering Panic Mode: $reason")
            BypassConfig.panicOptimize()
        }
    }
}
