with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DnsCacheManager.kt", "r") as f:
    text = f.read()

missing_methods = '''
    fun put(host: String, addresses: List<InetAddress>, ttlMs: Long = getDynamicTtl(), type: Int = 1) {
        if (addresses.isEmpty()) return
        val cacheKey = if (type == 1) host else "$host:$type"
        val expiry = System.currentTimeMillis() + ttlMs
        dnsCache[cacheKey] = Pair(addresses, expiry)
        negativeCache.remove(host)
        ensureEfficiency()
    }

    fun getCachedDetailed(host: String, type: Int = 1): List<DnsPacketEngine.DnsRecord>? {
        val cacheKey = if (type == 1) host else "$host:$type"
        val now = System.currentTimeMillis()
        detailedDnsCache[cacheKey]?.let { (records, expiry) ->
            if (now < expiry) return records
            detailedDnsCache.remove(cacheKey)
        }
        return null
    }

    private fun ensureEfficiency() {
        if (dnsCache.size > MAX_DNS_CACHE_SIZE) {
            clearExpired()
            if (dnsCache.size > MAX_DNS_CACHE_SIZE) {
                dnsCache.clear()
            }
        }
    }

    fun clearAll() {
        dnsCache.clear()
        detailedDnsCache.clear()
        negativeCache.clear()
    }
'''

# Insert missing methods before `fun putDetailed`
import re
text = re.sub(r'    fun putDetailed\(', missing_methods + '\n    fun putDetailed(', text)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DnsCacheManager.kt", "w") as f:
    f.write(text)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RobustResolver.kt", "r") as f:
    rtext = f.read()

rtext = rtext.replace("val aDeferred = kotlinx.coroutines.async {", "val aDeferred = async {")
rtext = rtext.replace("val aaaaDeferred = kotlinx.coroutines.async {", "val aaaaDeferred = async {")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RobustResolver.kt", "w") as f:
    f.write(rtext)
