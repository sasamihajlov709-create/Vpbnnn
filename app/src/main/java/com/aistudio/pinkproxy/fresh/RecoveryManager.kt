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

    fun handleEvent(event: RecoveryEvent, details: String = ""): Job {
        Log.w("RecoveryManager", "Reporting event to RecoveryStateMachine: $event ($details)")
        val signal: RecoverySignal = when (event) {
            RecoveryEvent.DPI_DETECTED -> RecoverySignal.DpiDetected(ProxyStats.currentDpiType.value)
            RecoveryEvent.TUNNEL_STALL -> RecoverySignal.TunnelStall(15000L, ProxyStats.activeConnections.value)
            RecoveryEvent.TCP_STALL -> RecoverySignal.TcpStall("", BypassConfig.strategy.value)
            RecoveryEvent.SSL_STALL -> RecoverySignal.SslStall("", BypassConfig.strategy.value)
            RecoveryEvent.DNS_FAILURE -> RecoverySignal.DnsFailure("", isPoisoned = false)
            RecoveryEvent.DNS_POISONED -> RecoverySignal.DnsFailure("", isPoisoned = true)
            RecoveryEvent.PROXY_UNREACHABLE -> RecoverySignal.ProxyUnresponsive(details)
            RecoveryEvent.MTU_EXCEEDED -> RecoverySignal.TunnelStall(5000L, 1)
            RecoveryEvent.HIGH_RTT -> RecoverySignal.ExtremeLatency(ProxyStats.lastLatency.value)
            RecoveryEvent.HANDSHAKE_FAILURE -> RecoverySignal.HealthDegraded("Handshake failure: $details")
            RecoveryEvent.CENSORSHIP_STALL -> RecoverySignal.SslStall("", BypassConfig.strategy.value)
        }
        return RecoveryStateMachine.postSignal(signal)
    }

    fun recalibrateEverything(): Job {
        Log.w("RecoveryManager", "Requesting full recalibration via RecoveryStateMachine")
        return RecoveryStateMachine.postSignal(RecoverySignal.ManualReset)
    }
}
