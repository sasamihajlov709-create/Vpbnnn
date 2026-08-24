with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiStrategySelector.kt", "r") as f:
    lines = f.readlines()

# Find getAverageScore start
start_idx = -1
for i, line in enumerate(lines):
    if "fun getAverageScore" in line:
        start_idx = i
        break

new_bottom = """    fun getAverageScore(strategy: BypassStrategy, profileId: String = NetworkProfileManager.currentProfile.value.id): Double {
        val states = StrategyStateRepository.getStates(strategy = strategy, profileId = profileId)
        if (states.isEmpty()) return 100.0
        val sumMean = states.sumOf { it.calculateBetaPosterior().first * 1000 }
        return sumMean / states.size
    }

    fun getStrategyMetrics(profileId: String = NetworkProfileManager.currentProfile.value.id): List<StrategyMetric> {
        return BypassStrategy.entries.map { strategy ->
            val states = StrategyStateRepository.getStates(strategy = strategy, profileId = profileId)
            val successes = states.sumOf { it.successCount.get().toLong() }
            val failures = states.sumOf { it.failureCount.get().toLong() }
            val ewmaLatencies = states.map { it.ewmaLatencyMs.get() }.filter { it > 0 }
            val avgRtt = if (ewmaLatencies.isNotEmpty()) ewmaLatencies.average().toLong() else 0L
            val score = getAverageScore(strategy, profileId).toInt()
            StrategyMetric(strategy, score, successes, failures, avgRtt)
        }.sortedByDescending { it.score }
    }

    fun getSelectionReasoning(strategy: BypassStrategy, host: String? = null): String {
        return "Bayesian Selection via Thompson Sampling - Selected ${strategy.name}"
    }
}
"""

if start_idx != -1:
    lines = lines[:start_idx]
    with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiStrategySelector.kt", "w") as f:
        f.writelines(lines)
        f.write(new_bottom)
