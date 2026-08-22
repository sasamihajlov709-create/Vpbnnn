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
         val calculatedIntensity = when (transport) {
             TransportType.TCP -> (
                 fingerprint.rstRate * 60 + 
                 fingerprint.sniBlockRate * 70 + 
                 fingerprint.timeoutRate * 30 + 
                 fingerprint.stallRate * 45
             ).toInt().coerceIn(0, 100)
             TransportType.UDP -> (
                 fingerprint.udpBlockRate * 85 + 
                 fingerprint.timeoutRate * 30
             ).toInt().coerceIn(0, 100)
             TransportType.DNS -> (
                 fingerprint.timeoutRate * 60 + 
                 fingerprint.rstRate * 40
             ).toInt().coerceIn(0, 100)
         }

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

         var recommendedMtu: Int? = null
         if (transport == TransportType.TCP && (fingerprint.timeoutRate > 0.35 || fingerprint.stallRate > 0.45)) {
             val currentMtu = BypassConfig.currentMtu.value
             if (currentMtu > 1000) {
                 recommendedMtu = currentMtu - 32
             }
         } else if (transport == TransportType.TCP && stability > 90 && globalSuccessRate > 90 && BypassConfig.currentMtu.value < 1400) {
             recommendedMtu = BypassConfig.currentMtu.value + 16
         }

         return PolicyDecision(
             targetIntensity = targetIntensity,
             calculatedStability = stability,
             recommendedMtu = recommendedMtu,
             shouldEnterPanic = shouldEnterPanic,
             shouldReset = shouldReset,
             affectedTransport = transport
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
        
        if (decision.shouldEnterPanic) {
            DpiEngine.enterPanicMode()
            RuntimeCoordinator.requestGlobalStrategyRotation(decision.affectedTransport, "Policy Panic Trigger")
        }
        if (decision.shouldReset) {
            resetAllEngineStates()
        }
    }

    fun onDpiEventDiagnosed(type: DpiType) {
        // Obsolete globally. Left empty or implement proper context-based boost in the future.
    }

    /**
     * Resets internal score weights and histories when severe anomalies dictate a clean slate.
     */
    fun resetAllEngineStates() {
        Log.w("DpiPolicyEngine", "Executing full state reset due to critical network anomaly policy trigger.")
        StrategyStateRepository.resetAll()
        DpiEngine.circuitBreakers.clear()
        DpiEngine.consecutiveFailures.clear()
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
        }
    }
}
