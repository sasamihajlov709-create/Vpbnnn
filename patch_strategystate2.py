with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "r") as f:
    lines = f.readlines()

out = []
for line in lines:
    if line.strip() == "}":
        pass # Handle closing brace separately
    out.append(line)

# Let's just find the exact index of `object StrategyStateRepository {` and insert before it
idx = -1
for i, line in enumerate(lines):
    if "object StrategyStateRepository {" in line:
        idx = i
        break

if idx != -1:
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
    # Wait, the closing brace for class StrategyState is before object StrategyStateRepository
    # Let's find the closing brace just before `object StrategyStateRepository`
    brace_idx = idx - 1
    while brace_idx > 0 and lines[brace_idx].strip() != "}":
        brace_idx -= 1
    
    if brace_idx > 0:
        lines.insert(brace_idx, addition.replace("}\n", "")) # Avoid double closing brace

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "w") as f:
    f.writelines(lines)
