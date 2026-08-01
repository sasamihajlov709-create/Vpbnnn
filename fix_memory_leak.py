import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    code = f.read()

old_init = """    init {
        BypassStrategy.entries.forEach {
            strategyStats[it] = StratStats()
        }
    }"""

new_init = """    init {
        BypassStrategy.entries.forEach {
            strategyStats[it] = StratStats()
        }
        ProxyDispatcher.mainScope.launch(ProxyDispatcher.io) {
            while (kotlinx.coroutines.isActive) {
                kotlinx.coroutines.delay(10 * 60 * 1000L) // 10 minutes
                val now = System.currentTimeMillis()
                
                // Cleanup memory
                val toRemove = hostStrategyMemory.filterValues { it.second < now }.keys
                toRemove.forEach { hostStrategyMemory.remove(it) }
                
                if (censorHeuristic.size > 2000) {
                    val toKeep = censorHeuristic.entries.sortedByDescending { it.value }.take(1000).associate { it.key to it.value }
                    censorHeuristic.clear()
                    censorHeuristic.putAll(toKeep)
                }
                
                val toRemoveLock = hostLockTime.filterValues { now - it > 300_000 }.keys
                toRemoveLock.forEach { hostLockTime.remove(it) }
                
                if (dnsProtocolScores.size > 1000) dnsProtocolScores.clear()
            }
        }
    }"""

if old_init in code:
    with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'w') as f:
        f.write(code.replace(old_init, new_init))
else:
    print("Could not find the block to replace")

