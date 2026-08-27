import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "r") as f:
    text = f.read()

replacement = """    fun restoreStates(states: Map<StrategyContextKey, StrategyMetricState>) {
        states.forEach { (key, metric) ->
            val state = getStrategyState(key.strategy, key.transport, key.category, key.profileId)
            state.score.set(metric.score)
            state.successCount.set(metric.successCount)
            state.failureCount.set(metric.failureCount)
            state.weightedSuccess.set(metric.weightedSuccess)
            state.weightedFailure.set(metric.weightedFailure)
            state.sampleCount.set(metric.successCount + metric.failureCount)
            state.verifiedSuccessCount.set(metric.verifiedSuccessCount)
            state.ewmaLatencyMs.set(metric.totalLatencyMs)
            state.restoreRecentLatencies(metric.recentLatencies)
            state.lastUsedTimestamp.set(metric.lastUsedTimestamp)
        }
    }"""

text = re.sub(r'    fun restoreStates\(states: Map<StrategyContextKey, StrategyMetricState>\) \{.*?\n    \}', replacement, text, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "w") as f:
    f.write(text)
