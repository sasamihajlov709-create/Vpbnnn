import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "r") as f:
    content = f.read()

# First, find the end of cleanupExpired function
# And cut everything after it, then rewrite clearProfileState, resetProfile, restoreStates

match = re.search(r'    fun cleanupExpired\(profileId: String\)\s*\{[^\}]+\}', content)
if match:
    base_content = content[:match.end()]
    rest = """
    
    fun clearProfileState(profileId: String) {
        contextStates.entries.removeIf { it.key.profileId == profileId }
        networkStrategyMemory.remove(profileId)
        contextualHostMemory.entries.removeIf { it.key.profileId == profileId }
        hostStrategyBlacklist.entries.removeIf { it.key.profileId == profileId }
        circuitBreakers.entries.removeIf { it.key.profileId == profileId }
        consecutiveFailures.entries.removeIf { it.key.profileId == profileId }
        consecutiveFailuresByHost.entries.removeIf { it.key.profileId == profileId }
        DpiEngine.eventHistory.entries.removeIf { it.key.profileId == profileId }
    }

    fun resetProfile(profileId: String) {
        contextStates.entries.removeIf { it.key.profileId == profileId }
        networkStrategyMemory.remove(profileId)
        contextualHostMemory.entries.removeIf { it.key.profileId == profileId }
        hostStrategyBlacklist.entries.removeIf { it.key.profileId == profileId }
        circuitBreakers.entries.removeIf { it.key.profileId == profileId }
        consecutiveFailures.entries.removeIf { it.key.profileId == profileId }
        consecutiveFailuresByHost.entries.removeIf { it.key.profileId == profileId }
        DpiEngine.eventHistory.entries.removeIf { it.key.profileId == profileId }
    }

    fun restoreStates(states: Map<StrategyContextKey, StrategyMetricState>) {
        states.forEach { (key, metric) ->
            val state = getStrategyState(key.strategy, key.transport, key.category, key.profileId)
            state.score.set(metric.score)
            state.successCount.set(metric.successCount)
            state.failureCount.set(metric.failureCount)
            state.weightedSuccess.set(metric.weightedSuccess)
            state.sampleCount.set(metric.successCount + metric.failureCount)
            state.verifiedSuccessCount.set(metric.verifiedSuccessCount)
            state.ewmaLatencyMs.set(metric.totalLatencyMs)
        }
    }
}
"""
    with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "w") as f:
        f.write(base_content + rest)
