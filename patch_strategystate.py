import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "r") as f:
    content = f.read()

# Add getRecentLatencies and restoreRecentLatencies
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
content = re.sub(r'    fun getP95Latency\(\): Long \{.*?\n    \}\n\n\n\}', lambda m: m.group(0).replace('\n}\n\n\n}', '\n    }\n' + addition), content, flags=re.DOTALL)

# Also update restoreStates to handle the new fields
# Wait, I need to see restoreStates first. Let's not blindly regex it yet.

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "w") as f:
    f.write(content)
