with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DnsCacheManager.kt", "r") as f:
    text = f.read()

import re

# Remove the extra '}' at line 134. We'll just replace the whole getCached and getCachedOrStale block.
old_block = r'''        return null
    }
    }

    fun getCachedOrStale\(host: String, type: Int = 1, maxStaleMs: Long = 24 \* 3600 \* 1000L\): List<InetAddress>\? \{
        ensureEfficiency\(\)
        if \(isIpAddress\(host\)\) \{
            return try \{ listOf\(InetAddress.getByName\(host\)\) \} catch \(e: Throwable\) \{ null \}
        \}
    \}'''

new_block = '''        return null
    }

    fun getCachedOrStale(host: String, type: Int = 1, maxStaleMs: Long = 24 * 3600 * 1000L): List<InetAddress>? {
        ensureEfficiency()
        if (isIpAddress(host)) {
            return try { listOf(InetAddress.getByName(host)) } catch (e: Throwable) { null }
        }
        val cacheKey = if (type == 1) host else "$host:$type"
        val now = System.currentTimeMillis()
        dnsCache[cacheKey]?.let { (addresses, expiry) ->
            if (now < expiry + maxStaleMs) {
                // Stale-While-Revalidate: Return stale cached IPs immediately, and trigger async background update
                ProxyDispatcher.mainScope.launch {
                    try {
                        RobustResolver.resolve(host, null, type)
                    } catch (e: Exception) {}
                }
                return getSortedIps(addresses)
            }
        }
        return getEmergencyFallback(host)
    }'''

text = re.sub(old_block, new_block, text)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DnsCacheManager.kt", "w") as f:
    f.write(text)
