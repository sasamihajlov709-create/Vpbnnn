with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiStrategySelector.kt", "r") as f:
    code = f.read()

import re

# We want to replace getAverageScore and getStrategyMetrics to include profileId
# Just replace the definitions
new_get_average = """    fun getAverageScore(strategy: BypassStrategy, profileId: String = NetworkProfileManager.currentProfile.value.id): Double {
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
    }"""

# regex search for old functions
pattern = r"    fun getAverageScore\(strategy: BypassStrategy\): Double \{.*?\}\n\n    fun getStrategyMetrics\(\): List<StrategyMetric> \{.*?\}\n"

code = re.sub(pattern, new_get_average + "\n", code, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiStrategySelector.kt", "w") as f:
    f.write(code)
