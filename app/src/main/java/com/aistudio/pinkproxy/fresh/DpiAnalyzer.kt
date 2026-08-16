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
        
        // Delegate DPI event policy response to Policy Engine
        DpiPolicyEngine.onDpiEventDiagnosed(DpiType.TCP_RESET)
    }

    fun recordEvent(type: DpiType) {
        DpiEngine.eventHistory.getOrPut(type) { AtomicInteger(0) }.incrementAndGet()
        DpiPolicyEngine.onDpiEventDiagnosed(type)
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
        } else {
            val globalSuccessRate = (totalSuccess.toDouble() / (totalSuccess + totalFailure) * 100)
            val fingerprint = getCensorshipFingerprint()
            val decision = DpiPolicyEngine.evaluatePolicy(fingerprint, globalSuccessRate, totalSuccess + totalFailure)
            DpiPolicyEngine.applyPolicyDecision(decision)
        }

        // Freshness decay of strategy bonuses without artificial inflation:
        // High scores (>100) gradually decay back towards baseline 100 when not actively reinforced.
        // Penalized scores (<100) are NOT artificially boosted without actual successful observations.
        DpiEngine.strategyScores.values.forEach { catScores ->
            catScores.values.forEach { score ->
                val s = score.get()
                if (s > 100) {
                    val decay = if (ProxyStats.censorshipIntensity.value / 100.0 > 0.8) 0.99 else 0.95
                    val decayed = (s * decay + 100 * (1.0 - decay)).toInt().coerceAtLeast(100)
                    score.set(decayed)
                }
            }
        }
        
        // Decay stale network strategy memory confidence
        val now = System.currentTimeMillis()
        DpiEngine.networkStrategyMemory.values.forEach { catMap ->
            catMap.entries.forEach { (cat, mem) ->
                val ageMs = now - mem.timestamp
                if (ageMs > 30 * 60 * 1000L && mem.confidence > 0.3) {
                    val newConf = (mem.confidence * 0.95).coerceAtLeast(0.3)
                    catMap[cat] = mem.copy(confidence = newConf)
                }
            }
        }
        
        BypassConfig.frag1 = DpiEngine.getRecommendedFragSize()
        BypassConfig.delay1 = DpiEngine.getRecommendedDelay()
        
        DpiEngine.pruneStrategies()
        decayEventHistory()

        if (totalSuccess + totalFailure > 1000) {
            DpiEngine.successHistory.forEach { (_, count) -> count.updateAndGet { (it * 0.5).toInt() } }
            DpiEngine.failureHistory.forEach { (_, count) -> count.updateAndGet { (it * 0.5).toInt() } }
            DpiEngine.weightedSuccessHistory.forEach { (_, count) -> count.updateAndGet { (it * 0.5).toLong() } }
            DpiEngine.categoryWeightedSuccessHistory.values.forEach { catMap ->
                catMap.values.forEach { count -> count.updateAndGet { (it * 0.5).toLong() } }
            }
        }
    }

    fun checkGlobalStall() {
        val totalSuccess = DpiEngine.successHistory.values.sumOf { it.get() }
        val totalFailure = DpiEngine.failureHistory.values.sumOf { it.get() }
        val total = totalSuccess + totalFailure
        if (total > 20) {
            val rate = (totalSuccess.toDouble() / total * 100)
            val fingerprint = getCensorshipFingerprint()
            val decision = DpiPolicyEngine.evaluatePolicy(fingerprint, rate, total)
            if (decision.shouldEnterPanic || decision.shouldReset) {
                DpiPolicyEngine.applyPolicyDecision(decision)
            }
        }
    }
}
