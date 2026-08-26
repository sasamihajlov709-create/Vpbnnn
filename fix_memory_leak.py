import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "r") as f:
    content = f.read()

# Add LruCache utility
lru_util = """
    private fun <K, V> createLruCache(maxSize: Int): MutableMap<K, V> {
        return java.util.Collections.synchronizedMap(object : java.util.LinkedHashMap<K, V>(maxSize, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<K, V>?): Boolean {
                return size > maxSize
            }
        })
    }
"""

if "createLruCache" not in content:
    content = content.replace("object StrategyStateRepository {", "object StrategyStateRepository {" + lru_util)

# Replace the specific ConcurrentHashMaps with LRU Caches
content = content.replace(
    "val contextualHostMemory = ConcurrentHashMap<HostContextKey, HostMemory>()",
    "val contextualHostMemory = createLruCache<HostContextKey, HostMemory>(2000)"
)
content = content.replace(
    "val consecutiveFailuresByHost = ConcurrentHashMap<HostFailureKey, AtomicInteger>()",
    "val consecutiveFailuresByHost = createLruCache<HostFailureKey, AtomicInteger>(2000)"
)
content = content.replace(
    "val hostStrategyBlacklist = ConcurrentHashMap<HostStrategyBlacklistKey, Long>()",
    "val hostStrategyBlacklist = createLruCache<HostStrategyBlacklistKey, Long>(2000)"
)

# Since getOrPut is an extension function that is lock-free only on ConcurrentMap, 
# for synchronized maps we might need to handle it or it works through standard MutableMap extension.
# kotlin's getOrPut on MutableMap works, but isn't atomic. It's fine for our use-case, but let's check.

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "w") as f:
    f.write(content)

print("Updated StrategyState.kt")
