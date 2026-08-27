with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "r") as f:
    text = f.read()

addition = """
    @Synchronized
    fun getRecentLatencies(): List<Long> {
        synchronized(recentLatencies) {
            val list = mutableListOf<Long>()
            for (i in 0 until latencyCount) {
                list.add(recentLatencies[i])
            }
            return list
        }
    }

    @Synchronized
    fun restoreRecentLatencies(latencies: List<Long>) {
        synchronized(recentLatencies) {
            val count = latencies.size.coerceAtMost(100)
            for (i in 0 until count) {
                recentLatencies[i] = latencies[i]
            }
            latencyCount = count
            latencyIndex = count % 100
            isP95Dirty = true
        }
    }
}
"""

text = text.replace("    }\n\n\n\n\nobject StrategyStateRepository", "    }\n" + addition + "\nobject StrategyStateRepository")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "w") as f:
    f.write(text)
