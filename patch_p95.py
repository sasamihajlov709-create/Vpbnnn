import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "r") as f:
    content = f.read()

replacement = """
    private var cachedP95: Long = 0L
    private var isP95Dirty: Boolean = false

    @Synchronized
    fun getP95Latency(): Long {
        synchronized(recentLatencies) {
            if (!isP95Dirty && latencyCount > 0) return cachedP95
            if (latencyCount == 0) return 0L
            val copy = LongArray(latencyCount)
            System.arraycopy(recentLatencies, 0, copy, 0, latencyCount)
            copy.sort()
            val p95Index = (latencyCount * 0.95).toInt().coerceAtMost(latencyCount - 1)
            cachedP95 = copy[p95Index]
            isP95Dirty = false
            return cachedP95
        }
    }
"""

content = re.sub(
    r'\s*@Synchronized\s*fun getP95Latency\(\): Long \{.*?\n    \}',
    replacement.lstrip('\n'),
    content,
    flags=re.DOTALL
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "w") as f:
    f.write(content)

