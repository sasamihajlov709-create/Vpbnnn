with open("app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt", "r") as f:
    content = f.read()

old_logic = """    fun rankCandidatesBayesian(candidates: List<BypassStrategy>, context: SelectionContext): List<BypassStrategy> {
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
    }"""

new_logic = """    fun rankCandidatesBayesian(candidates: List<BypassStrategy>, context: SelectionContext): List<BypassStrategy> {
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
                // Boost alpha proportionally to confidence and success count
                alpha += (hostMemory.successCount * hostMemory.confidence * 20.0) 
            }

            val sampled = ThompsonSampler.sampleBeta(alpha, beta)
            Pair(strategy, sampled)
        }
        return scored.sortedByDescending { it.second }.map { it.first }
    }"""

content = content.replace(old_logic, new_logic)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt", "w") as f:
    f.write(content)
