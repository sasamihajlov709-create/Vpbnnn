import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiStorage.kt", "r") as f:
    text = f.read()

replacement = """                ctxStates[key] = StrategyMetricState(
                    score = state.score.get(),
                    successCount = state.successCount.get(),
                    failureCount = state.failureCount.get(),
                    weightedSuccess = state.weightedSuccess.get(),
                    weightedFailure = state.weightedFailure.get(),
                    verifiedSuccessCount = state.verifiedSuccessCount.get(),
                    totalLatencyMs = state.ewmaLatencyMs.get(),
                    recentLatencies = state.getRecentLatencies(),
                    lastUsedTimestamp = state.lastUsedTimestamp.get()
                )"""

text = re.sub(r'                ctxStates\[key\] = StrategyMetricState\(\n                    score = state\.score\.get\(\),\n                    successCount = state\.successCount\.get\(\),\n                    failureCount = state\.failureCount\.get\(\),\n                    weightedSuccess = state\.weightedSuccess\.get\(\),\n                    verifiedSuccessCount = state\.verifiedSuccessCount\.get\(\),\n                    totalLatencyMs = state\.ewmaLatencyMs\.get\(\),\n                    lastUsedTimestamp = state\.lastUsedTimestamp\.get\(\)\n                \)', replacement, text, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiStorage.kt", "w") as f:
    f.write(text)
