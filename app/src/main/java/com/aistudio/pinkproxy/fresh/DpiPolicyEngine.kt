package com.aistudio.pinkproxy.fresh

import android.util.Log

/**
 * DpiPolicyEngine represents the Policy Decision Layer in the DPI subsystem.
 * 
 * Pipeline:
 * [DpiAnalyzer (Diagnosis)] -> [DpiPolicyEngine (Decision/Policy)] -> [DpiStrategySelector (Selection)]
 */
object DpiPolicyEngine {

    data class PolicyDecision(
        val targetIntensity: Int,
        val calculatedStability: Int,
        val recommendedMtu: Int?,
        val shouldEnterPanic: Boolean,
        val shouldReset: Boolean,
        val familyBoosts: List<StrategyFamily>,
        val affectedTransport: TransportType = TransportType.TCP
    )

    /**
     * Evaluates active policy based on diagnosis fingerprint and success rates.
     */
    fun evaluatePolicy(
        fingerprint: DpiAnalyzer.CensorshipFingerprint,
        globalSuccessRate: Double,
        totalObservations: Int,
        transport: TransportType = TransportType.TCP
    ): PolicyDecision {
        val currentIntensity = ProxyStats.censorshipIntensity.value
        val calculatedIntensity = (
            fingerprint.rstRate * 55 + 
            fingerprint.sniBlockRate * 65 + 
            fingerprint.timeoutRate * 25 + 
            fingerprint.stallRate * 40 + 
            fingerprint.udpBlockRate * 35
        ).toInt().coerceIn(0, 100)

        val shouldEnterPanic = (globalSuccessRate < 15.0 && calculatedIntensity > 40) ||
                               (totalObservations > 20 && (globalSuccessRate < 15.0 || fingerprint.timeoutRate > 0.8))
        val shouldReset = totalObservations > 20 && globalSuccessRate < 5.0

        val targetIntensity = if (calculatedIntensity > currentIntensity) {
            (currentIntensity * 0.2 + calculatedIntensity * 0.8).toInt()
        } else {
            if (globalSuccessRate > 95 && fingerprint.rstRate < 0.05 && fingerprint.sniBlockRate < 0.05) {
                (currentIntensity * 0.7 + calculatedIntensity * 0.3).toInt()
            } else {
                (currentIntensity * 0.9 + calculatedIntensity * 0.1).toInt()
            }
        }

        val stability = (
            globalSuccessRate * 0.5 + 
            (100.0 - (fingerprint.rstRate + fingerprint.sniBlockRate + fingerprint.timeoutRate) * 100.0).coerceAtLeast(0.0) * 0.5
        ).toInt().coerceIn(0, 100)

        val boosts = mutableListOf<StrategyFamily>()
        var recommendedMtu: Int? = null

        if (fingerprint.timeoutRate > 0.35 || fingerprint.stallRate > 0.45) {
            val currentMtu = BypassConfig.currentMtu.value
            if (currentMtu > 1000) {
                recommendedMtu = currentMtu - 32
            }
            boosts.add(StrategyFamily.TIMING)
            boosts.add(StrategyFamily.FRAGMENTATION)
        } else if (stability > 90 && globalSuccessRate > 90 && BypassConfig.currentMtu.value < 1400) {
            recommendedMtu = BypassConfig.currentMtu.value + 16
        }

        if (fingerprint.jitter > 600) {
            boosts.add(StrategyFamily.ADAPTIVE)
            boosts.add(StrategyFamily.TIMING)
        }

        val resolvedTransport = if (fingerprint.udpBlockRate > 0.6) {
            TransportType.UDP
        } else {
            transport
        }

        return PolicyDecision(
            targetIntensity = targetIntensity,
            calculatedStability = stability,
            recommendedMtu = recommendedMtu,
            shouldEnterPanic = shouldEnterPanic,
            shouldReset = shouldReset,
            familyBoosts = boosts,
            affectedTransport = resolvedTransport
        )
    }

    /**
     * Applies the policy decision to engine states, statistics, and configuration.
     */
    fun applyPolicyDecision(decision: PolicyDecision) {
        if (Math.abs(decision.targetIntensity - ProxyStats.censorshipIntensity.value) >= 1) {
            ProxyStats.updateCensorshipIntensity(decision.targetIntensity)
        }

        ProxyStats.updateStabilityScore(decision.calculatedStability)

        decision.recommendedMtu?.let { newMtu ->
            BypassConfig.setMtu(newMtu)
        }

        decision.familyBoosts.forEach { family ->
            DpiEngine.boostStrategyFamily(family, null)
        }

        if (decision.shouldEnterPanic) {
            DpiEngine.enterPanicMode()
            RuntimeCoordinator.requestGlobalStrategyRotation(decision.affectedTransport, "Policy Panic Trigger")
        }

        if (decision.shouldReset) {
            resetAllEngineStates()
        }
    }

    /**
     * Handles specific DPI event diagnosis by determining required strategy family boosts.
     */
    fun onDpiEventDiagnosed(type: DpiType) {
        when (type) {
            DpiType.TLS_SNI_BLOCK -> {
                DpiEngine.boostStrategyFamily(StrategyFamily.FRAGMENTATION, null)
                DpiEngine.boostStrategyFamily(StrategyFamily.TLS, null)
            }
            DpiType.UDP_BLOCK -> {
                DpiEngine.boostStrategyFamily(StrategyFamily.UDP, null)
            }
            DpiType.TCP_RESET -> {
                DpiEngine.boostStrategyFamily(StrategyFamily.TCP, null)
                DpiEngine.boostStrategyFamily(StrategyFamily.FRAGMENTATION, null)
                DpiEngine.boostStrategyFamily(StrategyFamily.TIMING, null)
            }
            DpiType.DNS_POISONING -> {
                DpiEngine.boostStrategyFamily(StrategyFamily.DNS, null)
            }
            DpiType.HTTP_BLOCK -> {
                DpiEngine.boostStrategyFamily(StrategyFamily.HTTP, null)
            }
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

    /**
     * Resets internal score weights and histories when severe anomalies dictate a clean slate.
     */
    fun resetAllEngineStates() {
        Log.w("DpiPolicyEngine", "Executing full state reset due to critical network anomaly policy trigger.")
        DpiEngine.strategyScores.values.forEach { catScores ->
            catScores.values.forEach { it.set(100) }
        }
        DpiEngine.circuitBreakers.clear()
        DpiEngine.consecutiveFailures.clear()
        DpiEngine.successHistory.clear()
        DpiEngine.failureHistory.clear()
        DpiEngine.weightedSuccessHistory.clear()
        DpiEngine.categorySuccessHistory.clear()
        DpiEngine.categoryFailureHistory.clear()
        DpiEngine.categoryWeightedSuccessHistory.clear()
    }

    /**
     * Records strategy substitution and degradation feedback when requested strategy differs from executed strategy.
     */
    fun recordStrategySubstitution(
        requested: BypassStrategy,
        effective: BypassStrategy,
        executed: BypassStrategy,
        host: String?,
        success: Boolean
    ) {
        if (requested != executed) {
            Log.d("DpiPolicyEngine", "Strategy substitution tracked: requested=$requested, effective=$effective, executed=$executed for host=$host (success=$success)")
            if (!success) {
                // Apply soft penalty to requested strategy to reduce repeat selection overhead
                DpiEngine.globalPenalties.getOrPut(requested) { java.util.concurrent.atomic.AtomicInteger(0) }.addAndGet(25)
            }
        }
    }
}
