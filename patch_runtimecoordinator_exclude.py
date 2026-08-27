import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RuntimeCoordinator.kt", "r") as f:
    text = f.read()

replacement = """        val strategyToExclude = failedStrategy
        val best = CandidateEngine.selectBest(ctx, excludeCurrent = strategyToExclude) ?: DpiStrategySelector.getDefaultFallback(transport)"""

text = re.sub(r'        val strategyToExclude = failedStrategy \?: BypassConfig\.getBestStrategyForHost\(host \?: "global", transport\)\n        val best = CandidateEngine\.selectBest\(ctx, excludeCurrent = strategyToExclude\) \?: DpiStrategySelector\.getDefaultFallback\(transport\)', replacement, text, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RuntimeCoordinator.kt", "w") as f:
    f.write(text)
