import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RuntimeCoordinator.kt', 'r') as f:
    content = f.read()

replacement = """
    suspend fun applyStrategyTransition(newStrategy: BypassStrategy, transport: TransportType, reason: String): Boolean = stateMutex.withLock {
        // Validate transport and registry executor compatibility
        val isFamilyValid = DpiStrategySelector.isFamilyCompatible(newStrategy.family, transport)
        val isExecutorValid = StrategyExecutionRegistry.isExecutorSupported(newStrategy, transport)

        val targetStrategy = if (isFamilyValid && isExecutorValid) {
            newStrategy
        } else {
            DpiStrategySelector.getDefaultFallback(transport)
        }

        Log.i(TAG, "Transitioning strategy for $transport to $targetStrategy. Reason: $reason")
        BypassConfig.applyInternalStrategy(targetStrategy)
        VpnRuntimeState.updateStrategy(targetStrategy.name, DpiStrategySelector.getSelectionReasoning(targetStrategy))
        return true
    }

    suspend fun rotateGlobalStrategy(
        transport: TransportType,
        reason: String,
        category: HostCategory = HostCategory.OTHER,
        profileId: String = "default"
    ): BypassStrategy {
        val candidates = BypassStrategy.entries.filter { 
            DpiStrategySelector.isFamilyCompatible(it.family, transport) &&
            StrategyExecutionRegistry.isExecutorSupported(it, transport)
        }
        val fallback = DpiStrategySelector.getDefaultFallback(transport)
        val best = candidates.maxByOrNull { strat ->
            val state = StrategyStateRepository.getStrategyState(strat, transport, category, profileId)
            val (posteriorMean, confidence) = state.calculateBetaPosterior()
            val baseWeighted = DpiStrategySelector.getAverageScore(strat)
            posteriorMean * (50.0 + 50.0 * confidence) + baseWeighted * 0.5
        } ?: fallback
        
        Log.i(TAG, "Rotating strategy for $transport [$category/$profileId] to $best. Reason: $reason")
        BypassConfig.applyInternalStrategy(best)
        VpnRuntimeState.updateStrategy(best.name, DpiStrategySelector.getSelectionReasoning(best))
        ProxyStats.logRecovery("Strategy rotated for $transport ($category): ${best.name} ($reason)")
        return best
    }
"""

content = re.sub(r'    suspend fun applyStrategyTransition.*?(?=    /\*\*|    fun requestGlobalStrategyRotation)', replacement, content, flags=re.DOTALL)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RuntimeCoordinator.kt', 'w') as f:
    f.write(content)
