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
        val intensity: Int,
        val transport: TransportType = TransportType.TCP
    )

    fun getCensorshipFingerprint(transport: TransportType = TransportType.TCP): CensorshipFingerprint {
        val relevantTypes = when (transport) {
            TransportType.TCP -> setOf(DpiType.TCP_RESET, DpiType.TLS_SNI_BLOCK, DpiType.CONNECTION_TIMEOUT, DpiType.HTTP_BLOCK, DpiType.TLS_HANDSHAKE_TIMEOUT, DpiType.BLACKHOLE, DpiType.TCP_STALL, DpiType.SSL_STALL, DpiType.MTU_EXCEEDED)
            TransportType.UDP -> setOf(DpiType.UDP_BLOCK, DpiType.CONNECTION_TIMEOUT, DpiType.BLACKHOLE, DpiType.MTU_EXCEEDED)
            TransportType.DNS -> setOf(DpiType.DNS_POISONING, DpiType.DNS_VERIFICATION_FAILURE, DpiType.CONNECTION_TIMEOUT)
        }

        val total = DpiEngine.eventHistory.filterKeys { it in relevantTypes }.values.sumOf { it.get() }.toDouble().coerceAtLeast(1.0)
        
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
            intensity = ProxyStats.censorshipIntensity.value,
            transport = transport
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

        val tcpStates = StrategyStateRepository.getAllContextStates().filterKeys { it.transport == TransportType.TCP }.values
        val udpStates = StrategyStateRepository.getAllContextStates().filterKeys { it.transport == TransportType.UDP }.values
        val dnsStates = StrategyStateRepository.getAllContextStates().filterKeys { it.transport == TransportType.DNS }.values

        val tcpSuccess = tcpStates.sumOf { it.successCount.get() }
        val tcpFailure = tcpStates.sumOf { it.failureCount.get() }
        val udpSuccess = udpStates.sumOf { it.successCount.get() }
        val udpFailure = udpStates.sumOf { it.failureCount.get() }
        val dnsSuccess = dnsStates.sumOf { it.successCount.get() }
        val dnsFailure = dnsStates.sumOf { it.failureCount.get() }
        
        if (DpiEngine.hostSpecificMemory.size > 1000) {
            val now = System.currentTimeMillis()
            val expiry = 86400000L * 7
            DpiEngine.hostSpecificMemory.entries.removeIf { now - it.value.timestamp > expiry }
            if (DpiEngine.hostSpecificMemory.size > 1500) DpiEngine.hostSpecificMemory.clear()
        }

        if (DpiEngine.consecutiveFailuresByHost.size > 2000) {
            DpiEngine.consecutiveFailuresByHost.clear()
        }
        
        if (DpiEngine.hostStrategyBlacklist.size > 1000) {
            val now = System.currentTimeMillis()
            DpiEngine.hostStrategyBlacklist.entries.removeIf { (_, strategies) ->
                strategies.entries.removeIf { now > it.value }
                strategies.isEmpty()
            }
        }

        if (DpiEngine.contextualHostMemory.size > 2000) {
            val now = System.currentTimeMillis()
            val expiry = 86400000L * 7
            DpiEngine.contextualHostMemory.entries.removeIf { now - it.value.timestamp > expiry }
            if (DpiEngine.contextualHostMemory.size > 3000) DpiEngine.contextualHostMemory.clear()
        }

        // Analyze TCP
        if (tcpSuccess + tcpFailure > 0) {
            val tcpSuccessRate = (tcpSuccess.toDouble() / (tcpSuccess + tcpFailure) * 100)
            val fingerprint = getCensorshipFingerprint(TransportType.TCP)
            val decision = DpiPolicyEngine.evaluatePolicy(fingerprint, tcpSuccessRate, tcpSuccess + tcpFailure, TransportType.TCP)
            DpiPolicyEngine.applyPolicyDecision(decision)
        }

        // Analyze UDP
        if (udpSuccess + udpFailure > 0) {
            val udpSuccessRate = (udpSuccess.toDouble() / (udpSuccess + udpFailure) * 100)
            val fingerprint = getCensorshipFingerprint(TransportType.UDP)
            val decision = DpiPolicyEngine.evaluatePolicy(fingerprint, udpSuccessRate, udpSuccess + udpFailure, TransportType.UDP)
            DpiPolicyEngine.applyPolicyDecision(decision)
        }

        // Analyze DNS
        if (dnsSuccess + dnsFailure > 0) {
            val dnsSuccessRate = (dnsSuccess.toDouble() / (dnsSuccess + dnsFailure) * 100)
            val fingerprint = getCensorshipFingerprint(TransportType.DNS)
            val decision = DpiPolicyEngine.evaluatePolicy(fingerprint, dnsSuccessRate, dnsSuccess + dnsFailure, TransportType.DNS)
            DpiPolicyEngine.applyPolicyDecision(decision)
        }

        val totalSuccess = tcpSuccess + udpSuccess + dnsSuccess
        val totalFailure = tcpFailure + udpFailure + dnsFailure
        
        if (totalSuccess + totalFailure == 0) {
            ProxyStats.updateCensorshipIntensity((ProxyStats.censorshipIntensity.value - 2).coerceAtLeast(0))
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
        
        decayEventHistory()

        if (totalSuccess + totalFailure > 1000) {
            val states = StrategyStateRepository.getAllContextStates().values
            states.forEach { state ->
                state.successCount.updateAndGet { (it * 0.5).toInt() }
                state.failureCount.updateAndGet { (it * 0.5).toInt() }
                state.weightedSuccess.updateAndGet { (it * 0.5).toLong() }
            }
        }
        BypassConfig.cleanupExpiredHeuristics()
    }

    fun checkGlobalStall(transport: TransportType = TransportType.TCP) {
        val states = StrategyStateRepository.getAllContextStates().filterKeys { it.transport == transport }.values
        val totalSuccess = states.sumOf { it.successCount.get() }
        val totalFailure = states.sumOf { it.failureCount.get() }
        val total = totalSuccess + totalFailure
        if (total > 20) {
            val rate = (totalSuccess.toDouble() / total * 100)
            val fingerprint = getCensorshipFingerprint(transport)
            val decision = DpiPolicyEngine.evaluatePolicy(fingerprint, rate, total, transport)
            if (decision.shouldEnterPanic || decision.shouldReset) {
                DpiPolicyEngine.applyPolicyDecision(decision)
            }
        }
    }
}
