package com.aistudio.pinkproxy.fresh

import android.util.Log
import java.util.concurrent.atomic.AtomicInteger

object DpiAnalyzer {
    data class CensorshipFingerprint(
        val rstRate: Double,
        val sniBlockRate: Double,
        val udpBlockRate: Double,
        val dnsBlockRate: Double,
        val timeoutRate: Double,
        val stallRate: Double,
        val jitter: Double,
        val intensity: Int,
        val transport: TransportType
    )

    fun getCensorshipFingerprint(transport: TransportType): CensorshipFingerprint {
        val currentProfileId = NetworkProfileManager.currentProfile.value.id
        val relevantTypes = when (transport) {
            TransportType.TCP -> setOf(DpiType.TCP_RESET, DpiType.TLS_SNI_BLOCK, DpiType.CONNECTION_TIMEOUT, DpiType.HTTP_BLOCK, DpiType.TLS_HANDSHAKE_TIMEOUT, DpiType.BLACKHOLE, DpiType.TCP_STALL, DpiType.SSL_STALL, DpiType.MTU_EXCEEDED)
            TransportType.UDP -> setOf(DpiType.UDP_BLOCK, DpiType.CONNECTION_TIMEOUT, DpiType.BLACKHOLE, DpiType.MTU_EXCEEDED)
            TransportType.DNS -> setOf(DpiType.DNS_POISONING, DpiType.DNS_VERIFICATION_FAILURE, DpiType.CONNECTION_TIMEOUT)
        }

        val profileEvents = DpiEngine.eventHistory.filterKeys { it.profileId == currentProfileId && it.transport == transport }
        val total = profileEvents.filterKeys { it.type in relevantTypes }.values.sumOf { it.get() }.toDouble().coerceAtLeast(1.0)
        
        val rttKey = "${currentProfileId}|$transport"
        val transportHistory = DpiEngine.rttHistory[rttKey]?.let { synchronized(it) { it.toList() } } ?: emptyList()
        val jitter = if (transportHistory.size > 2) {
            val diffs = transportHistory.zipWithNext { a, b -> Math.abs(a - b) }
            diffs.average()
        } else 0.0
        
        fun getEventCount(type: DpiType): Int {
            return profileEvents[DpiEventKey(currentProfileId, transport, type)]?.get() ?: 0
        }

        return CensorshipFingerprint(
            rstRate = getEventCount(DpiType.TCP_RESET) / total,
            sniBlockRate = getEventCount(DpiType.TLS_SNI_BLOCK) / total,
            udpBlockRate = getEventCount(DpiType.UDP_BLOCK) / total,
            dnsBlockRate = (getEventCount(DpiType.DNS_POISONING) + getEventCount(DpiType.DNS_VERIFICATION_FAILURE)) / total,
            timeoutRate = getEventCount(DpiType.CONNECTION_TIMEOUT) / total,
            stallRate = (getEventCount(DpiType.TCP_STALL) + getEventCount(DpiType.SSL_STALL)) / total,
            jitter = jitter,
            intensity = ProxyStats.censorshipIntensity.value,
            transport = transport
        )
    }

    fun decayEventHistory(profileId: String) {
        val total = DpiEngine.eventHistory.filterKeys { it.profileId == profileId }.values.sumOf { it.get() }
        if (total > 500) {
            DpiEngine.eventHistory.forEach { (key, count) ->
                if (key.profileId == profileId) {
                    count.updateAndGet { (it * 0.9).toInt() }
                }
            }
        }
    }

    fun recordSpoofedRst(host: String, rttMs: Long) {
        Log.w("DpiAnalyzer", "SPOOFED TCP RST DETECTED for $host (RTT=${rttMs}ms). Active DPI middlebox injected packet.")
        val profileId = NetworkProfileManager.currentProfile.value.id
        DpiEngine.eventHistory.getOrPut(DpiEventKey(profileId, TransportType.TCP, DpiType.TCP_RESET)) { AtomicInteger(0) }.incrementAndGet()
    }

    fun recordEvent(type: DpiType, transport: TransportType) {
        val profileId = NetworkProfileManager.currentProfile.value.id
        DpiEngine.eventHistory.getOrPut(DpiEventKey(profileId, transport, type)) { AtomicInteger(0) }.incrementAndGet()
    }

    fun analyzeAndAdjust() {
        val currentProfileId = NetworkProfileManager.currentProfile.value.id
        StrategyStateRepository.cleanupExpired(currentProfileId)

        if (StrategyStateRepository.consecutiveFailuresByHost.size > 500) {
            StrategyStateRepository.consecutiveFailuresByHost.entries.removeIf { it.value.get() == 0 }
            if (StrategyStateRepository.consecutiveFailuresByHost.size > 1000) StrategyStateRepository.consecutiveFailuresByHost.clear()
        }

        val tcpStates = StrategyStateRepository.getStates(profileId = currentProfileId, transport = TransportType.TCP)
        val udpStates = StrategyStateRepository.getStates(profileId = currentProfileId, transport = TransportType.UDP)
        val dnsStates = StrategyStateRepository.getStates(profileId = currentProfileId, transport = TransportType.DNS)

        val tcpSuccess = tcpStates.sumOf { it.successCount.get() }
        val tcpFailure = tcpStates.sumOf { it.failureCount.get() }
        val udpSuccess = udpStates.sumOf { it.successCount.get() }
        val udpFailure = udpStates.sumOf { it.failureCount.get() }
        val dnsSuccess = dnsStates.sumOf { it.successCount.get() }
        val dnsFailure = dnsStates.sumOf { it.failureCount.get() }


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

        // Update global UI metrics exactly once per cycle
        DpiPolicyEngine.aggregateGlobalMetrics()

        val totalSuccess = tcpSuccess + udpSuccess + dnsSuccess
        val totalFailure = tcpFailure + udpFailure + dnsFailure
        
        if (totalSuccess + totalFailure == 0) {
            ProxyStats.updateCensorshipIntensity((ProxyStats.censorshipIntensity.value - 2).coerceAtLeast(0))
        }

        // Decay stale network strategy memory confidence for current profile
        val now = System.currentTimeMillis()
        StrategyStateRepository.networkStrategyMemory[currentProfileId]?.entries?.forEach { (cat, mem) ->
            val ageMs = now - mem.timestamp
            if (ageMs > 30 * 60 * 1000L && mem.confidence > 0.3) {
                val newConf = (mem.confidence * 0.95).coerceAtLeast(0.3)
                StrategyStateRepository.networkStrategyMemory[currentProfileId]?.put(cat, mem.copy(confidence = newConf))
            }
        }
        
        decayEventHistory(currentProfileId)

        if (totalSuccess + totalFailure > 1000) {
            val states = StrategyStateRepository.getStates(profileId = currentProfileId)
            states.forEach { state ->
                state.successCount.updateAndGet { (it * 0.5).toInt() }
                state.failureCount.updateAndGet { (it * 0.5).toInt() }
                state.weightedSuccess.updateAndGet { (it * 0.5).toLong() }
            }
        }
        BypassConfig.cleanupExpiredHeuristics()
    }

    fun checkGlobalStall(transport: TransportType) {
        val currentProfileId = NetworkProfileManager.currentProfile.value.id
        val states = StrategyStateRepository.getStates(profileId = currentProfileId, transport = transport)
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
