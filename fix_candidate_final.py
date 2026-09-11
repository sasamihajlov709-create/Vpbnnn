text = """package com.aistudio.pinkproxy.fresh

/**
 * CandidateEngine unifies the strategy filtering and ranking rules across the entire app.
 * It replaces scattered `.filter { ... }` blocks with a single source of truth for
 * circuit breakers, blacklists, transport compatibility, and strict mode checks.
 */
object CandidateEngine {

    data class SelectionContext(
        val transport: TransportType,
        val profileId: String = NetworkProfileManager.currentProfile.value.id,
        val host: String? = null,
        val category: HostCategory = HostCategory.OTHER,
        val currentStrategy: BypassStrategy? = null,
        val isDiagnosticMode: Boolean = false,
        val ignoreHostBlacklist: Boolean = false
    )

    /**
     * Returns a list of all strategies that are eligible for the given context.
     */
    fun getEligibleCandidates(
        context: SelectionContext, 
        baseList: List<BypassStrategy> = BypassStrategy.entries
    ): List<BypassStrategy> {
        return baseList.filter { StrategyPolicyGate.isAllowed(it, context) }
    }

    /**
     * Unified method for selecting the best strategy, replacing scattered logic.
     */
    fun selectBest(
        context: SelectionContext,
        excludeCurrent: BypassStrategy? = null
    ): BypassStrategy? {
        val candidates = getEligibleCandidates(context)
        val filtered = if (excludeCurrent != null) candidates.filter { it != excludeCurrent } else candidates
        if (filtered.isEmpty()) return null
        val ranked = rankCandidatesBayesian(filtered, context)
        return ranked.firstOrNull()
    }

    /**
     * Ranks the given eligible candidates using Bayesian Thompson Sampling based on the context.
     */
    fun rankCandidatesBayesian(
        candidates: List<BypassStrategy>,
        context: SelectionContext
    ): List<BypassStrategy> {
        // Hierarchical Prior Learning
        // Level 1: Host-specific memory (Highest Confidence)
        val hostMemory = context.host?.let { 
            StrategyStateRepository.contextualHostMemory[HostContextKey(it, context.transport, context.profileId)] 
        }

        val hostFails = context.host?.let {
            StrategyStateRepository.consecutiveFailuresByHost[HostFailureKey(context.profileId, it, context.transport)]?.get()
        } ?: 0

        val currentActive = context.currentStrategy ?: BypassConfig.getStrategyForTransport(context.transport).value

        val scored: List<Pair<BypassStrategy, Pair<Double, ExplainableTelemetry>>> = candidates.map { strategy ->
            // Level 3: Global Prior for this transport + profile (aggregate across all categories)
            val allStatesForStrategy = StrategyStateRepository.getStates(profileId = context.profileId, transport = context.transport, strategy = strategy)
            val globalSuccess = allStatesForStrategy.sumOf { it.weightedSuccess.get() } / 1000.0
            val globalFailure = allStatesForStrategy.sumOf { it.weightedFailure.get() } / 1000.0

            val transportHealth = StrategyStateRepository.getTransportHealth(context.profileId, context.transport)

            // Base priors start at 1.0, plus 20% of the aggregated global knowledge
            var alpha = 1.0 + (globalSuccess * 0.2)
            var beta = 1.0 + (globalFailure * 0.2)
            
            // If the transport is globally failing, artificially inflate beta to suppress exploration
            if (transportHealth < 0.2) {
                beta += 50.0 * (0.2 - transportHealth)
            }

            // Level 2: Category-specific Prior (e.g. STREAMING, SOCIAL)
            val state = StrategyStateRepository.getStrategyState(strategy, context.transport, context.category, context.profileId)
            val lastUsed = state.lastUsedTimestamp.get()
            val timeDecay = if (lastUsed > 0) Math.max(0.1, 1.0 - ((System.currentTimeMillis() - lastUsed) / (24.0 * 3600.0 * 1000.0)) * 0.05) else 1.0
            alpha += (state.weightedSuccess.get() / 1000.0) * timeDecay
            beta += (state.weightedFailure.get() / 1000.0) * timeDecay 
            
            // Level 1: Apply Host Memory bonus if the strategy matches the known best host strategy and no active host failures
            if (hostMemory != null && hostMemory.strategy == strategy && hostMemory.successCount > 0 && hostFails == 0) {
                val hostDecay = Math.max(0.1, 1.0 - (System.currentTimeMillis() - hostMemory.timestamp) / (24.0 * 3600.0 * 1000.0))
                val boost = Math.min(50.0, hostMemory.successCount * hostMemory.confidence * 5.0) * hostDecay
                alpha += boost
            }

            // STABLE mode prior boost for device verified strategies
            val isModeStable = BypassConfig.autoTuningMode == AutoTuningMode.STABLE
            val verificationBonus = if (strategy.validationStatus == ValidationStatus.DEVICE_VERIFIED || (state.verifiedSuccessCount.get() >= 5 && state.failureCount.get() == 0)) {
                if (isModeStable) 100.0 else 10.0
            } else if (isModeStable && strategy.validationStatus == ValidationStatus.UNVERIFIED && state.verifiedSuccessCount.get() == 0) {
                // Penalize unverified strategies heavily in stable mode
                -100.0
            } else 0.0

            val sampledProb = ThompsonSampler.sampleBeta(alpha, beta)
            
            // Stage 3 Utility Function Calibration
            // Phase 4: Dynamic Risk and Cost based on observedFailureRate, observedLatency, and Sample Confidence
            val observedLatency = state.getP95Latency().toDouble()
            val wSuccess = state.weightedSuccess.get().toDouble()
            val wFailure = state.weightedFailure.get().toDouble()
            
            // Effective sample count ensures that if weighted data decays, our confidence also decays, triggering re-exploration.
            val effectiveSamples = (wSuccess + wFailure) / 2.0 // Assuming average observation weight is 2.0
            
            val confidence = if (effectiveSamples > 0) Math.min(1.0, effectiveSamples / 15.0) else 0.0
            val observedFailureRate = if (effectiveSamples > 0) (wFailure / (wSuccess + wFailure)) else 0.0
            
            // If we have few samples, we assume moderate risk (1.5). As samples grow, we trust the actual observed failure rate.
            val riskPenalty = (observedFailureRate * 5.0) * confidence + (1.0 - confidence) * 1.5
            val dynamicRisk = strategy.risk.toDouble() + riskPenalty
            val dynamicCost = strategy.cost.toDouble() + (observedLatency / 1000.0) // 1 second latency adds 1.0 cost

            // Memory Bonus Normalization [0..1]
            val memoryScore = if (hostMemory != null && hostMemory.strategy == strategy && hostMemory.successCount > 0 && hostFails == 0) {
                1.0 * (hostMemory.successCount.toDouble() / (hostMemory.successCount + hostFails).coerceAtLeast(1))
            } else if (hostMemory != null && hostFails > 0 && hostMemory.strategy == strategy) {
                -1.0
            } else 0.0

            val verificationScore = if (strategy.validationStatus == ValidationStatus.DEVICE_VERIFIED || (state.verifiedSuccessCount.get() >= 5 && state.failureCount.get() == 0)) {
                1.0
            } else if (isModeStable && strategy.validationStatus == ValidationStatus.UNVERIFIED && state.verifiedSuccessCount.get() == 0) {
                -0.5
            } else 0.0

            // Normalization of bounds
            val normProb = sampledProb.coerceIn(0.0, 1.0)
            val normBandwidth = ((10.0 - dynamicCost).coerceAtLeast(0.0)) / 10.0
            val normRisk = (1.0 - (dynamicRisk / 15.0)).coerceIn(0.0, 1.0)

            // Calculate Utility Using Strict Weights (Sum of weights ~ 1.0)
            val wProb = 0.40
            val wMemory = 0.30
            val wVerification = 0.10
            val wBandwidth = 0.10
            val wRisk = 0.10

            val baseUtility = (normProb * wProb) + 
                              (memoryScore * wMemory) + 
                              (verificationScore * wVerification) + 
                              (normBandwidth * wBandwidth) + 
                              (normRisk * wRisk)

            val telemetry = ExplainableTelemetry(
                strategyName = strategy.name,
                alpha = alpha,
                beta = beta,
                sampledProbability = normProb,
                hostMemoryBonus = memoryScore * wMemory,
                verificationBonus = verificationScore * wVerification,
                hysteresisBonus = 0.0, // Hysteresis applied at the end
                dynamicRisk = dynamicRisk,
                dynamicCost = dynamicCost,
                expectedBandwidth = normBandwidth,
                totalUtility = baseUtility
            )
            
            Pair(strategy, Pair(baseUtility, telemetry))
        }

        val sorted = scored.sortedByDescending { it.second.first }
        
        if (sorted.isEmpty()) return emptyList()

        // Hysteresis step: Only switch if the best candidate is significantly better than current active
        val bestCandidate = sorted.first()
        var winner = bestCandidate
        
        if (currentActive != null && bestCandidate.first != currentActive) {
            val currentScoreObj = sorted.find { it.first == currentActive }
            if (currentScoreObj != null) {
                val currentUtility = currentScoreObj.second.first
                val bestUtility = bestCandidate.second.first
                
                val switchMargin = when (BypassConfig.autoTuningMode) {
                    AutoTuningMode.STABLE -> 0.15 // Require 15% better utility to switch
                    AutoTuningMode.EXPLORATION -> 0.05
                    AutoTuningMode.DIAGNOSTIC -> 0.01
                }
                
                if (bestUtility < currentUtility + switchMargin) {
                    winner = currentScoreObj
                }
            }
        }

        // Push telemetry for the winner to the UI
        VpnRuntimeState.updateTelemetry(winner.second.second)
        
        // Put the winner at the top of the list, followed by the rest
        val finalRanked = mutableListOf(winner.first)
        sorted.forEach { 
            if (it.first != winner.first) finalRanked.add(it.first) 
        }
        
        return finalRanked
    }
}
"""

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt', 'w') as f:
    f.write(text)

