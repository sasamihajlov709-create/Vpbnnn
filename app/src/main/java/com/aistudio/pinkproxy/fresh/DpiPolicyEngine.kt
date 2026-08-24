package com.aistudio.pinkproxy.fresh

import android.util.Log

object DpiPolicyEngine {

    data class PolicyDecision(
        val targetIntensity: Int,
        val calculatedStability: Int,
        val recommendedMtu: Int?,
        val shouldEnterPanic: Boolean,
        val shouldReset: Boolean,
        val affectedTransport: TransportType
    )

         fun evaluatePolicy(
         fingerprint: DpiAnalyzer.CensorshipFingerprint,
         globalSuccessRate: Double,
         totalObservations: Int,
         transport: TransportType
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
                 fingerprint.dnsBlockRate * 80
             ).toInt().coerceIn(0, 100)
         }

         val shouldEnterPanic = (globalSuccessRate < 15.0 && calculatedIntensity > 40) ||
                                (totalObservations > 20 && (globalSuccessRate < 15.0 || fingerprint.timeoutRate > 0.8))

         val shouldReset = totalObservations > 20 && globalSuccessRate < 5.0

         val targetIntensity = if (calculatedIntensity > currentIntensity) {
             (currentIntensity * 0.2 + calculatedIntensity * 0.8).toInt()
         } else {
             if (globalSuccessRate > 95 && fingerprint.rstRate < 0.05 && fingerprint.sniBlockRate < 0.05 && fingerprint.dnsBlockRate < 0.05) {
                 (currentIntensity * 0.7 + calculatedIntensity * 0.3).toInt()
             } else {
                 (currentIntensity * 0.9 + calculatedIntensity * 0.1).toInt()
             }
         }

         val stability = (
             globalSuccessRate * 0.5 + 
             (100.0 - (fingerprint.rstRate + fingerprint.sniBlockRate + fingerprint.udpBlockRate + fingerprint.dnsBlockRate + fingerprint.timeoutRate) * 100.0).coerceAtLeast(0.0) * 0.5
         ).toInt().coerceIn(0, 100)

         var recommendedMtu: Int? = null
         if (transport == TransportType.TCP && (fingerprint.timeoutRate > 0.35 || fingerprint.stallRate > 0.45)) {
             val currentMtu = BypassConfig.getMtuForTransport(transport)
             if (currentMtu > 1000) {
                 recommendedMtu = currentMtu - 32
             }
         } else if (transport == TransportType.TCP && stability > 90 && globalSuccessRate > 90 && BypassConfig.getMtuForTransport(transport) < 1400) {
             recommendedMtu = BypassConfig.getMtuForTransport(transport) + 16
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

    
    data class TransportPolicyState(
        var mtu: Int = 1500,
        var isPanicMode: Boolean = false,
        var calculatedIntensity: Int = 0
    )

    val transportPolicies = java.util.concurrent.ConcurrentHashMap<TransportType, TransportPolicyState>().apply {
        put(TransportType.TCP, TransportType.TCP.let { TransportPolicyState() })
        put(TransportType.UDP, TransportType.UDP.let { TransportPolicyState() })
        put(TransportType.DNS, TransportType.DNS.let { TransportPolicyState() })
    }

    fun applyPolicyDecision(decision: PolicyDecision) {
        val policy = transportPolicies.getOrPut(decision.affectedTransport) { TransportPolicyState() }
        
        policy.calculatedIntensity = decision.targetIntensity
        
        decision.recommendedMtu?.let { newMtu ->
            policy.mtu = newMtu
        }
        
        if (decision.shouldEnterPanic) {
            policy.isPanicMode = true
            RuntimeCoordinator.requestGlobalStrategyRotation(decision.affectedTransport, "Policy Panic Trigger")
        } else {
            policy.isPanicMode = false
        }
        
        // Aggregate global metrics based on transport policies
        aggregateGlobalMetrics()

        if (decision.shouldReset) {
            resetProfileEngineStates(NetworkProfileManager.currentProfile.value.id)
        }
    }

    private fun aggregateGlobalMetrics() {
        val tcpIntensity = transportPolicies[TransportType.TCP]?.calculatedIntensity ?: 0
        val udpIntensity = transportPolicies[TransportType.UDP]?.calculatedIntensity ?: 0
        val dnsIntensity = transportPolicies[TransportType.DNS]?.calculatedIntensity ?: 0
        
        // Aggregate censorship intensity (weighted towards TCP as the most common protocol)
        val globalIntensity = (tcpIntensity * 0.5 + udpIntensity * 0.3 + dnsIntensity * 0.2).toInt()
        
        if (Math.abs(globalIntensity - ProxyStats.censorshipIntensity.value) >= 1) {
            ProxyStats.updateCensorshipIntensity(globalIntensity)
        }
    }
        fun onDpiEventDiagnosed(type: DpiType) {
        // Obsolete globally. Left empty or implement proper context-based boost in the future.
    }

        fun resetProfileEngineStates(profileId: String) {
        Log.w("DpiPolicyEngine", "Executing state reset for profile $profileId due to critical network anomaly policy trigger.")
        StrategyStateRepository.resetProfile(profileId)
        // DpiEngine maps usually use strategy as key, so it might need some other clearance, but clear() affects everything.
        // For now let's just clear for the specific strategy if possible, or clear circuit breakers since they are transient anyway.
        }

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
