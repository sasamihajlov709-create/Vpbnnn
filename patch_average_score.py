with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiStrategySelector.kt", "r") as f:
    code = f.read()

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
            val avgRtt = if (states.isNotEmpty()) states.map { it.averageLatencyMs }.average().toLong() else 0L
            val score = getAverageScore(strategy, profileId).toInt()
            StrategyMetric(strategy, score, successes, failures, avgRtt)
        }.sortedByDescending { it.score }
    }"""

old_get_average = """    fun getAverageScore(strategy: BypassStrategy): Double {
        val states = StrategyStateRepository.getStates(strategy = strategy)
        if (states.isEmpty()) return 100.0
        val sumMean = states.sumOf { it.calculateBetaPosterior().first * 1000 }
        return sumMean / states.size
    }

    fun getStrategyMetrics(): List<StrategyMetric> {
        return BypassStrategy.entries.map { strategy ->
            val states = StrategyStateRepository.getStates(strategy = strategy)
            val successes = states.sumOf { it.successCount.get().toLong() }
            val failures = states.sumOf { it.failureCount.get().toLong() }
            val avgRtt = if (states.isNotEmpty()) states.map { it.averageLatencyMs }.average().toLong() else 0L
            val score = getAverageScore(strategy).toInt()
            StrategyMetric(strategy, score, successes, failures, avgRtt)
        }.sortedByDescending { it.score }
    }"""

code = code.replace(old_get_average, new_get_average)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiStrategySelector.kt", "w") as f:
    f.write(code)
