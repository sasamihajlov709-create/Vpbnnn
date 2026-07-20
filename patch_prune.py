with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

import re

new_code = """
    fun recordHostConsecutiveFailure(host: String, count: Int) { 
        hostConsecutiveFailures[host] = count 
        pruneMemoryIfNeeded()
    }
    
    fun pruneMemoryIfNeeded() {
        if (hostConsecutiveFailures.size > 500) {
            hostConsecutiveFailures.keys.take(100).forEach { hostConsecutiveFailures.remove(it) }
        }
        if (hostDnas.size > 500) {
            val now = System.currentTimeMillis()
            val toRemove = hostDnas.entries.filter { now - it.value.lastSuccess > 86400000 }.map { it.key }
            toRemove.forEach { hostDnas.remove(it) }
            if (hostDnas.size > 500) hostDnas.keys.take(100).forEach { hostDnas.remove(it) }
        }
        if (hostStrategyCache.size > 1000) hostStrategyCache.keys.take(200).forEach { hostStrategyCache.remove(it) }
        if (hostSuccessStrategies.size > 500) hostSuccessStrategies.keys.take(100).forEach { hostSuccessStrategies.remove(it) }
        if (hostSuccessCount.size > 500) hostSuccessCount.keys.take(100).forEach { hostSuccessCount.remove(it) }
        if (hostTtlMap.size > 500) hostTtlMap.keys.take(100).forEach { hostTtlMap.remove(it) }
    }
"""

content = re.sub(
    r'fun recordHostConsecutiveFailure\(host: String, count: Int\) \{.*?if \(hostDnas.size > 1000\) \{.*?\}\s*\}',
    new_code.strip(),
    content,
    flags=re.DOTALL
)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
