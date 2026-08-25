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
    fun rankCandidatesBayesian(candidates: List<BypassStrategy>, context: SelectionContext): List<BypassStrategy> {
        // Hierarchical Prior
        // Level 1: Host-specific memory
        val hostMemory = context.host?.let { 
            StrategyStateRepository.contextualHostMemory[HostContextKey(it, context.transport, context.profileId)] 
        }

        val scored = candidates.map { strategy ->
            val state = StrategyStateRepository.getStrategyState(strategy, context.transport, context.category, context.profileId)
            
            var alpha = 1.0 + (state.weightedSuccess.get() / 1000.0)
            var beta = 1.0 + (state.weightedFailure.get() / 1000.0) // Note: using weightedFailure directly
            
            // Apply Host Memory bonus if the strategy matches the known best host strategy
            if (hostMemory != null && hostMemory.strategy == strategy && hostMemory.successCount > 0) {
                // Boost alpha proportionally to confidence and success count
                alpha += (hostMemory.successCount * hostMemory.confidence * 10.0) 
            }

            val sampled = ThompsonSampler.sampleBeta(alpha, beta)
            Pair(strategy, sampled)
        }
        return scored.sortedByDescending { it.second }.map { it.first }
    }
}
