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
    fun handleEvent(event: RecoveryEvent, details: String = "") {
        Log.w("RecoveryManager", "Handling event: $event ($details)")
        ProxyStats.logRecovery("Event: $event")
        
        when (event) {
            RecoveryEvent.DNS_FAILURE -> {
                RobustResolver.clearCache()
                // Avoid full panic on single DNS failure
                if (ProxyStats.dnsFailureCount.value > 10) {
                    triggerPanic("Repeated DNS failures")
                }
            }
            RecoveryEvent.PROXY_UNREACHABLE -> {
                triggerPanic("Proxy unreachable")
            }
            RecoveryEvent.TUNNEL_STALL -> {
                triggerPanic("Tunnel stall detected")
            }
            RecoveryEvent.HIGH_RTT -> {
                BypassConfig.rotateGlobalStrategy()
            }
            RecoveryEvent.HANDSHAKE_FAILURE -> {
                BypassConfig.rotateGlobalStrategy()
            }
        }
    }

    private fun triggerPanic(reason: String) {
        if (!BypassConfig.isPanicMode) {
            Log.w("RecoveryManager", "Triggering Panic Mode: $reason")
            BypassConfig.panicOptimize()
        }
    }
}
