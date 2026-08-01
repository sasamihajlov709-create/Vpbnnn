import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    code = f.read()

old = """        ProxyDispatcher.mainScope.launch(ProxyDispatcher.io) {
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
        }"""

new = """        ProxyDispatcher.mainScope.launch(ProxyDispatcher.io) {
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
            }
        }"""
new = new.replace("while (kotlinx.coroutines.isActive)", "while (kotlinx.coroutines.currentCoroutineContext()[kotlinx.coroutines.Job]?.isActive == true)")

if old in code:
    with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'w') as f:
        f.write(code.replace(old, new))
else:
    print("Could not find the block to replace")

