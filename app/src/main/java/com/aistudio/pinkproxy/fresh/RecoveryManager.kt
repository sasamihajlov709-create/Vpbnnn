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
                        if (rate > 80) {
                            val reduction = if (rate > 95) 2 else 1
                            RecoveryStateMachine.coolDownEscalation(reduction)
                            Log.i("RecoveryManager", "Strategy cooling: RecoveryStateMachine escalation reduced by $reduction")
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
