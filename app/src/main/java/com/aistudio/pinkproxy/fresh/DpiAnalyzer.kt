package com.aistudio.pinkproxy.fresh

import android.util.Log
import java.util.concurrent.atomic.AtomicInteger

object DpiAnalyzer {

    data class CensorshipFingerprint(
        val rstRate: Double,
        val sniBlockRate: Double,
        val udpBlockRate: Double,
        val timeoutRate: Double,
        val stallRate: Double,
        val jitter: Double,
        val intensity: Int
    )

    fun getCensorshipFingerprint(): CensorshipFingerprint {
        val total = DpiEngine.eventHistory.values.sumOf { it.get() }.toDouble().coerceAtLeast(1.0)
        
        val allHistory = DpiEngine.rttHistory.values.flatMap { synchronized(it) { it.toList() } }
        val jitter = if (allHistory.size > 2) {
            val diffs = allHistory.zipWithNext { a, b -> Math.abs(a - b) }
            diffs.average()
        } else 0.0

        return CensorshipFingerprint(
            rstRate = (DpiEngine.eventHistory[DpiType.TCP_RESET]?.get() ?: 0) / total,
            sniBlockRate = (DpiEngine.eventHistory[DpiType.TLS_SNI_BLOCK]?.get() ?: 0) / total,
            udpBlockRate = (DpiEngine.eventHistory[DpiType.UDP_BLOCK]?.get() ?: 0) / total,
            timeoutRate = (DpiEngine.eventHistory[DpiType.CONNECTION_TIMEOUT]?.get() ?: 0) / total,
            stallRate = ((DpiEngine.eventHistory[DpiType.TCP_STALL]?.get() ?: 0) + (DpiEngine.eventHistory[DpiType.SSL_STALL]?.get() ?: 0)) / total,
            jitter = jitter,
            intensity = ProxyStats.censorshipIntensity.value
        )
    }

    fun decayEventHistory() {
        val total = DpiEngine.eventHistory.values.sumOf { it.get() }
        if (total > 500) {
            DpiEngine.eventHistory.forEach { (_, count) ->
                count.updateAndGet { (it * 0.9).toInt() }
            }
        }
    }

    fun recordSpoofedRst(host: String, rttMs: Long) {
        Log.w("DpiAnalyzer", "SPOOFED TCP RST DETECTED for $host (RTT=${rttMs}ms). Active DPI middlebox injected packet.")
        DpiEngine.eventHistory.getOrPut(DpiType.TCP_RESET) { AtomicInteger(0) }.incrementAndGet()
        
        // Boost TCP Out-of-order, Zero Window, and TTL Skew desynchronization strategies immediately
        DpiEngine.boostStrategyFamily(StrategyFamily.TCP, null)
        DpiEngine.boostStrategyFamily(StrategyFamily.TIMING, null)
        DpiEngine.boostStrategyFamily(StrategyFamily.FRAGMENTATION, null)
    }

    fun recordEvent(type: DpiType) {
        DpiEngine.eventHistory.getOrPut(type) { AtomicInteger(0) }.incrementAndGet()
        
        when (type) {
            DpiType.TLS_SNI_BLOCK -> {
                DpiEngine.boostStrategyFamily(StrategyFamily.FRAGMENTATION, null)
                DpiEngine.boostStrategyFamily(StrategyFamily.TLS, null)
            }
            DpiType.UDP_BLOCK -> DpiEngine.boostStrategyFamily(StrategyFamily.UDP, null)
            DpiType.TCP_RESET -> {
                DpiEngine.boostStrategyFamily(StrategyFamily.TCP, null)
                DpiEngine.boostStrategyFamily(StrategyFamily.FRAGMENTATION, null)
                DpiEngine.boostStrategyFamily(StrategyFamily.TIMING, null)
            }
            DpiType.DNS_POISONING -> DpiEngine.boostStrategyFamily(StrategyFamily.DNS, null)
            DpiType.HTTP_BLOCK -> DpiEngine.boostStrategyFamily(StrategyFamily.HTTP, null)
            DpiType.TLS_HANDSHAKE_TIMEOUT -> {
                DpiEngine.boostStrategyFamily(StrategyFamily.TLS, null)
                DpiEngine.boostStrategyFamily(StrategyFamily.TIMING, null)
            }
            DpiType.CONNECTION_TIMEOUT -> {
                DpiEngine.boostStrategyFamily(StrategyFamily.FRAGMENTATION, null)
                DpiEngine.boostStrategyFamily(StrategyFamily.TCP, null)
            }
            DpiType.TCP_STALL, DpiType.SSL_STALL -> {
                DpiEngine.boostStrategyFamily(StrategyFamily.FRAGMENTATION, null)
                DpiEngine.boostStrategyFamily(StrategyFamily.TCP, null)
                DpiEngine.boostStrategyFamily(StrategyFamily.TIMING, null)
            }
            else -> {}
        }
    }

    fun analyzeAndAdjust() {
        if (DpiEngine.hostStrategyBlacklist.size > 500) {
            val now = System.currentTimeMillis()
            DpiEngine.hostStrategyBlacklist.entries.removeIf { map -> map.value.values.all { it < now } }
            if (DpiEngine.hostStrategyBlacklist.size > 1000) DpiEngine.hostStrategyBlacklist.clear()
        }
        
        if (DpiEngine.consecutiveFailuresByHost.size > 500) {
            DpiEngine.consecutiveFailuresByHost.entries.removeIf { it.value.get() == 0 }
            if (DpiEngine.consecutiveFailuresByHost.size > 1000) DpiEngine.consecutiveFailuresByHost.clear()
        }

        val totalSuccess = DpiEngine.successHistory.values.sumOf { it.get() }
        val totalFailure = DpiEngine.failureHistory.values.sumOf { it.get() }
        
        if (DpiEngine.hostSpecificMemory.size > 1000) {
            val now = System.currentTimeMillis()
            val expiry = 86400000L * 7
            DpiEngine.hostSpecificMemory.entries.removeIf { now - it.value.timestamp > expiry }
            if (DpiEngine.hostSpecificMemory.size > 1500) DpiEngine.hostSpecificMemory.clear()
        }

        if (totalSuccess + totalFailure == 0) {
            ProxyStats.updateCensorshipIntensity((ProxyStats.censorshipIntensity.value - 2).coerceAtLeast(0))
            return
        }

        val globalSuccessRate = (totalSuccess.toDouble() / (totalSuccess + totalFailure) * 100).toInt()
        val fingerprint = getCensorshipFingerprint()
        val calculatedIntensity = (fingerprint.rstRate * 55 + fingerprint.sniBlockRate * 65 + fingerprint.timeoutRate * 25 + fingerprint.stallRate * 40 + fingerprint.udpBlockRate * 35).toInt().coerceIn(0, 100)

        if (globalSuccessRate < 15 && calculatedIntensity > 40) {
            DpiEngine.enterPanicMode()
        }

        val targetIntensity = if (calculatedIntensity > ProxyStats.censorshipIntensity.value) {
            (ProxyStats.censorshipIntensity.value * 0.2 + calculatedIntensity * 0.8).toInt()
        } else {
            if (globalSuccessRate > 95 && fingerprint.rstRate < 0.05 && fingerprint.sniBlockRate < 0.05) {
                (ProxyStats.censorshipIntensity.value * 0.7 + calculatedIntensity * 0.3).toInt()
            } else {
                (ProxyStats.censorshipIntensity.value * 0.9 + calculatedIntensity * 0.1).toInt()
            }
        }
        
        if (Math.abs(targetIntensity - ProxyStats.censorshipIntensity.value) >= 1) {
            ProxyStats.updateCensorshipIntensity(targetIntensity)
        }

        val stability = (globalSuccessRate * 0.5 + (100 - (fingerprint.rstRate + fingerprint.sniBlockRate + fingerprint.timeoutRate) * 100).coerceAtLeast(0.0) * 0.5).toInt().coerceIn(0, 100)
        ProxyStats.updateStabilityScore(stability)
        
        if (fingerprint.timeoutRate > 0.35 || fingerprint.stallRate > 0.45) {
             val mtu = BypassConfig.currentMtu.value
             if (mtu > 1000) BypassConfig.setMtu(mtu - 32)
             DpiEngine.boostStrategyFamily(StrategyFamily.TIMING, null)
             DpiEngine.boostStrategyFamily(StrategyFamily.FRAGMENTATION, null)
        } else if (stability > 90 && globalSuccessRate > 90 && BypassConfig.currentMtu.value < 1400) {
             BypassConfig.setMtu(BypassConfig.currentMtu.value + 16)
        }
        
        if (fingerprint.jitter > 600) {
            DpiEngine.boostStrategyFamily(StrategyFamily.ADAPTIVE, null)
            DpiEngine.boostStrategyFamily(StrategyFamily.TIMING, null)
        }

        DpiEngine.strategyScores.values.forEach { catScores ->
            catScores.values.forEach { score ->
                val s = score.get()
                val decay = if (ProxyStats.censorshipIntensity.value / 100.0 > 0.8) 0.99 else 0.95
                if (s > 100) score.set((s * decay + 100 * (1.0 - decay)).toInt())
                else if (s < 100) score.set((s * 1.01 + 2).toInt().coerceAtMost(100))
            }
        }
        
        BypassConfig.frag1 = DpiEngine.getRecommendedFragSize()
        BypassConfig.delay1 = DpiEngine.getRecommendedDelay()
        
        DpiEngine.pruneStrategies()
        decayEventHistory()

        if (totalSuccess + totalFailure > 1000) {
            DpiEngine.successHistory.forEach { (_, count) -> count.updateAndGet { (it * 0.5).toInt() } }
            DpiEngine.failureHistory.forEach { (_, count) -> count.updateAndGet { (it * 0.5).toInt() } }
        }
    }

    fun checkGlobalStall() {
        val total = DpiEngine.successHistory.values.sumOf { it.get() } + DpiEngine.failureHistory.values.sumOf { it.get() }
        if (total > 20) {
            val rate = (DpiEngine.successHistory.values.sumOf { it.get() }.toDouble() / total * 100)
            val fingerprint = getCensorshipFingerprint()
            
            if ((rate < 15 || fingerprint.timeoutRate > 0.8)) {
                DpiEngine.enterPanicMode()
                BypassConfig.rotateGlobalStrategy()
                if (rate < 5) resetEverything()
            }
        }
    }

    private fun resetEverything() {
        DpiEngine.strategyScores.values.forEach { catScores ->
            catScores.values.forEach { it.set(100) }
        }
        DpiEngine.circuitBreakers.clear()
        DpiEngine.consecutiveFailures.clear()
        DpiEngine.successHistory.clear()
        DpiEngine.failureHistory.clear()
    }
}
