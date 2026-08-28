import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DnsCacheManager.kt", "r") as f:
    text = f.read()

replacement = """    fun getCached(host: String, type: Int = 1): List<InetAddress>? {
        ensureEfficiency()
        if (isIpAddress(host)) {
            return try { listOf(InetAddress.getByName(host)) } catch (e: Throwable) { null }
        }
        val cacheKey = if (type == 1) host else "$host:$type"
        val now = System.currentTimeMillis()
        dnsCache[cacheKey]?.let { (addresses, expiry) ->
            if (now < expiry) {
                // If cache is about to expire (in <20% of TTL), trigger background refresh early
                if (expiry - now < CACHE_TTL_MS / 5) {
                    ProxyDispatcher.mainScope.launch {
                        try {
                            RobustResolver.resolve(host, null, type)
                        } catch (e: Exception) {}
                    }
                }
                return getSortedIps(addresses)
            } else {
                dnsCache.remove(cacheKey)
            }
        }
        return null
    }"""

text = re.sub(r'    fun getCached\(host: String, type: Int = 1\): List<InetAddress>\? \{.*?    \}', replacement, text, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DnsCacheManager.kt", "w") as f:
    f.write(text)
