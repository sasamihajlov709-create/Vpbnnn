import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RuntimeCoordinator.kt', 'r') as f:
    content = f.read()

# Fix the broken rotateGlobalStrategy
replacement = """        val fallback = DpiStrategySelector.getDefaultFallback(transport)
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
    }"""

content = re.sub(r'        val fallback = DpiStrategySelector\.getDefaultFallback.*?best\n    \}', replacement, content, flags=re.DOTALL)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RuntimeCoordinator.kt', 'w') as f:
    f.write(content)
