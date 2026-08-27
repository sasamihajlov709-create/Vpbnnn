with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "r") as f:
    text = f.read()

import re
text = re.sub(r'    @Synchronized\n    fun getRecentLatencies.*?(?=\nobject StrategyStateRepository)', '', text, flags=re.DOTALL)

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

text = text.replace("}\n\nobject StrategyStateRepository", addition + "\nobject StrategyStateRepository")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "w") as f:
    f.write(text)
