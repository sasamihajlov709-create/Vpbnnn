package com.aistudio.pinkproxy.fresh

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
        val category: HostCategory = HostCategory.OTHER
    )

    /**
     * Evaluates whether a strategy is currently allowed to execute under the given context.
     */
    fun isEligible(strategy: BypassStrategy, context: SelectionContext, ignoreHostBlacklist: Boolean = false): Boolean {
        val now = System.currentTimeMillis()
        
        // 0. Implementation Status (Skip STUB in dynamic selection)
        if (strategy.implementationStatus == ImplementationStatus.STUB) return false
        
        // 1. Check Family Compatibility
        if (!DpiStrategySelector.isFamilyCompatible(strategy.family, context.transport)) return false
        
        // 2. Check Executor Registration
        if (!StrategyExecutionRegistry.isExecutorSupported(strategy, context.transport)) return false
        
        // 3. Global Strict Mode
        if (BypassConfig.isStrictBypassMode && strategy == BypassStrategy.DIRECT) return false

        // 4. Panic Mode Check
        val isPanic = BypassConfig.isPanicModeForTransport(context.transport) || BypassConfig.getIntensityForTransport(context.transport) > 92
        if (isPanic && (strategy.group == StrategyGroup.LIGHT || strategy.group == StrategyGroup.MEDIUM)) return false
        
        // 5. Global Circuit Breakers (By Profile + Transport)
        val cbKey = CircuitBreakerKey(context.profileId, context.transport, strategy)
        if ((StrategyStateRepository.circuitBreakers[cbKey] ?: 0L) > now) return false
        
        // 6. Host-Specific Blacklists
        if (!ignoreHostBlacklist && context.host != null) {
            val blKey = HostStrategyBlacklistKey(context.host, context.transport, context.profileId, strategy)
            if ((StrategyStateRepository.hostStrategyBlacklist[blKey] ?: 0L) > now) return false
        }
        
        return true
    }

    /**
     * Returns a list of all strategies that are eligible for the given context.
     */
    fun getEligibleCandidates(
        context: SelectionContext, 
        baseList: List<BypassStrategy> = BypassStrategy.entries, 
        ignoreHostBlacklist: Boolean = false
    ): List<BypassStrategy> {
        return baseList.filter { isEligible(it, context, ignoreHostBlacklist) }
    }
    
    /**
     * Ranks the given eligible candidates using Bayesian Thompson Sampling based on the context.
     */
    
    /**
     * Unified method for selecting the best strategy, replacing scattered logic.
     */
    fun selectBest(
        context: SelectionContext,
        excludeCurrent: BypassStrategy? = null,
        ignoreHostBlacklist: Boolean = false
    ): BypassStrategy? {
        val candidates = getEligibleCandidates(context, ignoreHostBlacklist = ignoreHostBlacklist)
        val filtered = if (excludeCurrent != null) candidates.filter { it != excludeCurrent } else candidates
        if (filtered.isEmpty()) return null
        val ranked = rankCandidatesBayesian(filtered, context)
        return ranked.firstOrNull()
    }

    fun rankCandidatesBayesian(candidates: List<BypassStrategy>, context: SelectionContext): List<BypassStrategy> {
        // Hierarchical Prior Learning

        // Level 1: Host-specific memory (Highest Confidence)
        val hostMemory = context.host?.let { 
            StrategyStateRepository.contextualHostMemory[HostContextKey(it, context.transport, context.profileId)] 
        }

        val scored = candidates.map { strategy ->
            // Level 3: Global Prior for this transport + profile (aggregate across all categories)
            val allStatesForStrategy = StrategyStateRepository.getStates(profileId = context.profileId, transport = context.transport, strategy = strategy)
            val globalSuccess = allStatesForStrategy.sumOf { it.weightedSuccess.get() } / 1000.0
            val globalFailure = allStatesForStrategy.sumOf { it.weightedFailure.get() } / 1000.0

            // Base priors start at 1.0, plus 20% of the aggregated global knowledge
            var alpha = 1.0 + (globalSuccess * 0.2)
            var beta = 1.0 + (globalFailure * 0.2)

            // Level 2: Category-specific Prior (e.g. STREAMING, SOCIAL)
            val state = StrategyStateRepository.getStrategyState(strategy, context.transport, context.category, context.profileId)
            alpha += (state.weightedSuccess.get() / 1000.0)
            beta += (state.weightedFailure.get() / 1000.0) 
            
            // Level 1: Apply Host Memory bonus if the strategy matches the known best host strategy
            if (hostMemory != null && hostMemory.strategy == strategy && hostMemory.successCount > 0) {
                val decay = Math.max(0.1, 1.0 - (System.currentTimeMillis() - hostMemory.timestamp) / (24.0 * 3600.0 * 1000.0))
                val boost = Math.min(50.0, hostMemory.successCount * hostMemory.confidence * 5.0) * decay
                alpha += boost
            }

            val sampledProb = ThompsonSampler.sampleBeta(alpha, beta)
            
            // Stage 3 Utility Function Calibration
            // Dynamic Risk and Cost based on observedFailureRate and observedLatency
            val observedLatency = state.getP95Latency().toDouble()
            val totalSamples = state.sampleCount.get().toDouble()
            val observedFailureRate = if (totalSamples > 0) state.failureCount.get().toDouble() / totalSamples else 0.0
            
            val dynamicRisk = strategy.risk.toDouble() + (observedFailureRate * 5.0)
            val normalizedLatency = (observedLatency / 200.0).coerceIn(0.0, 5.0)
            val dynamicCost = strategy.cost.toDouble() + normalizedLatency

            val hostMemoryBonus = if (hostMemory != null && hostMemory.strategy == strategy && hostMemory.successCount > 0) {
                150.0 * hostMemory.confidence
            } else 0.0

            val expectedBandwidth = (10.0 - dynamicCost).coerceAtLeast(1.0)
            val utility = (sampledProb * 100.0) + hostMemoryBonus + (expectedBandwidth * 0.5) - (dynamicRisk * 0.2 + dynamicCost * 0.2)
            
            Pair(strategy, utility)
        }
        return scored.sortedByDescending { it.second }.map { it.first }
    }
}
