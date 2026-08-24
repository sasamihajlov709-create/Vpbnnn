import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiStrategySelector.kt", "r") as f:
    content = f.read()

# Replace the validStrategies block
valid_strat_pattern = r"val validStrategies = BypassStrategy\.entries\.filter \{ strategy ->.*?\} \)"
new_valid_strat = """val ctx = CandidateEngine.SelectionContext(transport, profileId, host, category)
        val validStrategies = CandidateEngine.getEligibleCandidates(ctx)"""

content = re.sub(r"val validStrategies = BypassStrategy\.entries\.filter \{ strategy ->[\s\S]*?\(!BypassConfig\.isStrictBypassMode \|\| strategy != BypassStrategy\.DIRECT\)\n        \}", new_valid_strat, content)

# Replace the getBestExtremeStrategy extremeCandidates filtering block
extreme_strat_pattern = r"val extremeCandidates = BypassStrategy\.entries\.filter \{[\s\S]*?\(host == null \|\| \(StrategyStateRepository\.hostStrategyBlacklist\[HostStrategyBlacklistKey\(host, transport, profileId, it\)\] \?: 0L\) < now\) \n        \}"
new_extreme_strat = """val ctx = CandidateEngine.SelectionContext(transport, profileId, host, HostCategory.OTHER)
        val extremeCandidates = CandidateEngine.getEligibleCandidates(ctx, BypassStrategy.entries.filter { it.group == StrategyGroup.EXTREME })"""

content = re.sub(extreme_strat_pattern, new_extreme_strat, content)

# Remove ThompsonSampler block from getBestStrategy
thompson_pattern = r"// Bayesian Top-K Candidate Selection \(Thompson Sampling\)[\s\S]*?return best \?: getDefaultFallback\(transport\)"
new_thompson = """// Bayesian Top-K Candidate Selection (Thompson Sampling)
        val ranked = CandidateEngine.rankCandidatesBayesian(validStrategies, ctx)
        return ranked.firstOrNull() ?: getDefaultFallback(transport)"""
content = re.sub(thompson_pattern, new_thompson, content)


# Remove ThompsonSampler block from getBestExtremeStrategy
thompson_ext_pattern = r"val candidates = extremeCandidates\.map \{ strategy ->[\s\S]*?return candidates\.maxByOrNull \{ it\.second \}\?\.first \?: getDefaultExtremeFallback\(transport\)"
new_thompson_ext = """val ranked = CandidateEngine.rankCandidatesBayesian(extremeCandidates, ctx)
        return ranked.firstOrNull() ?: getDefaultExtremeFallback(transport)"""
content = re.sub(thompson_ext_pattern, new_thompson_ext, content)


with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiStrategySelector.kt", "w") as f:
    f.write(content)

