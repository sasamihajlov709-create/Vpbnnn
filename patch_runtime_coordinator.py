with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RuntimeCoordinator.kt", "r") as f:
    content = f.read()

old_ctx = "val ctx = CandidateEngine.SelectionContext(transport, profileId, null, category)"
new_ctx = "val ctx = CandidateEngine.SelectionContext(transport, profileId, host, category)"

old_logic = """        val candidates = CandidateEngine.getEligibleCandidates(ctx)
        val fallback = DpiStrategySelector.getDefaultFallback(transport)
        val ranked = CandidateEngine.rankCandidatesBayesian(candidates, ctx)
        val best = ranked.firstOrNull() ?: fallback"""

new_logic = """        val currentStrategy = BypassConfig.getBestStrategyForHost(host ?: "global", transport)
        val best = CandidateEngine.selectBest(ctx, excludeCurrent = currentStrategy) ?: DpiStrategySelector.getDefaultFallback(transport)"""

content = content.replace(old_ctx, new_ctx)
content = content.replace(old_logic, new_logic)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RuntimeCoordinator.kt", "w") as f:
    f.write(content)
