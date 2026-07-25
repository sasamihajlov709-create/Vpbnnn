package com.aistudio.pinkproxy.fresh

import android.util.Log

enum class RecoveryEvent {
    DNS_FAILURE,
    PROXY_UNREACHABLE,
    TUNNEL_STALL,
    HIGH_RTT,
    HANDSHAKE_FAILURE
}

object RecoveryManager {
    private var lastRestartTime = 0L
    private val RESTART_COOLDOWN = 60000L // 1 minute

    fun handleEvent(event: RecoveryEvent, details: String = "") {
        Log.w("RecoveryManager", "Handling event: $event ($details)")
        ProxyStats.logRecovery("Event: $event ($details)")
        
        when (event) {
            RecoveryEvent.DNS_FAILURE -> {
                RobustResolver.clearCache()
                if (ProxyStats.dnsFailureCount.value > 15) {
                    triggerPanic("Repeated DNS failures")
                    requestServiceRestart("Persistent DNS failures")
                }
            }
            RecoveryEvent.PROXY_UNREACHABLE -> {
                triggerPanic("Proxy unreachable")
                requestServiceRestart("Proxy crash or unreachable")
            }
            RecoveryEvent.TUNNEL_STALL -> {
                triggerPanic("Tunnel stall detected")
                requestServiceRestart("Data flow stalled")
            }
            RecoveryEvent.HIGH_RTT -> {
                BypassConfig.rotateGlobalStrategy()
            }
            RecoveryEvent.HANDSHAKE_FAILURE -> {
                BypassConfig.rotateGlobalStrategy()
            }
        }
    }

    private fun requestServiceRestart(reason: String) {
        val now = System.currentTimeMillis()
        if (now - lastRestartTime < RESTART_COOLDOWN) {
            Log.w("RecoveryManager", "Skipping restart: cooldown active ($reason)")
            return
        }
        
        lastRestartTime = now
        Log.e("RecoveryManager", "Requesting Service Restart: $reason")
        
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
