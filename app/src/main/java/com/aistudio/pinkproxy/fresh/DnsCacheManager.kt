package com.aistudio.pinkproxy.fresh

import android.util.Log
import java.net.InetAddress
import java.net.Inet6Address
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.launch

object DnsCacheManager {
    private const val CACHE_TTL_MS = 10 * 60 * 1000L // 10 minutes
    private const val MAX_DNS_CACHE_SIZE = 1000
    private const val NEGATIVE_CACHE_TTL = 300000L // 5 minutes
    
    private val dnsCache = ConcurrentHashMap<String, Pair<List<InetAddress>, Long>>() // Long is expiry time
    private val detailedDnsCache = ConcurrentHashMap<String, Pair<List<DnsPacketEngine.DnsRecord>, Long>>()
    private val echSupportCache = ConcurrentHashMap<String, Boolean>()
    private val ipHeatmap = ConcurrentHashMap<String, Int>()
    private val ipRtt = ConcurrentHashMap<String, Long>()
    private val negativeCache = ConcurrentHashMap<String, Long>()
    
    private val resolverBlacklist = ConcurrentHashMap<String, Long>()
    private val resolverSuccess = ConcurrentHashMap<String, Int>()
    private val resolverFailure = ConcurrentHashMap<String, Int>()

    private val poisonedIps = java.util.Collections.synchronizedSet(mutableSetOf(
        "127.0.0.1", "0.0.0.0", "10.10.10.10", "192.168.1.1", "1.2.3.4",
        "203.0.113.1", "198.51.100.1", "146.112.61.106",
        "10.10.34.34", "10.10.34.35", "93.184.216.34",
        "37.228.114.22", "8.254.218.126", "212.188.7.20", "195.82.146.120",
        "95.167.13.50", "95.167.13.49", "213.180.204.3", "213.180.204.1",
        "213.180.193.3", "198.101.242.72", "23.253.163.53", "195.82.146.114",
        "185.112.82.16", "82.200.130.206", "217.16.20.12",
        "62.213.63.174", "104.244.42.1", "199.16.156.231", "162.159.138.232"
    ))

    private val staticIps = mapOf(
        "dns.google" to listOf("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888"),
        "cloudflare-dns.com" to listOf("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111"),
        "dns.quad9.net" to listOf("9.9.9.9", "149.112.112.112"),
        "doh.opendns.com" to listOf("208.67.222.222", "208.67.220.220"),
        "google.com" to listOf("142.250.190.46", "142.250.180.14"),
        "facebook.com" to listOf("157.240.22.35", "157.240.1.35"),
        "github.com" to listOf("140.82.112.4", "140.82.113.3", "140.82.114.3"),
        "telegram.org" to listOf("149.154.167.99", "149.154.167.51", "149.154.165.120", "149.154.160.1"),
        "t.me" to listOf("149.154.167.99", "149.154.175.50"),
        "instagram.com" to listOf("157.240.22.174"),
        "twitter.com" to listOf("104.244.42.193", "104.244.42.65"),
        "x.com" to listOf("104.244.42.193", "104.244.42.65")
    )

    private val bogonIps = setOf(
        "127.0.0.1", "0.0.0.0", "10.0.0.1", "255.255.255.255", "::1", "::"
    )

    private val emergencyFallback = mapOf(
        "youtube.com" to listOf("142.250.180.142", "142.251.46.206", "172.217.16.206"),
        "googlevideo.com" to listOf("173.194.220.33", "74.125.167.165"),
        "telegram.org" to listOf("149.154.167.99", "149.154.167.51", "91.108.56.110"),
        "google.com" to listOf("8.8.8.8", "142.250.180.14", "142.250.185.110"),
        "github.com" to listOf("140.82.112.4", "140.82.121.3"),
        "wikipedia.org" to listOf("103.102.166.224"),
        "discord.com" to listOf("162.159.138.232", "162.159.135.232"),
        "reddit.com" to listOf("151.101.1.140", "151.101.65.140")
    )

    private val poisonedPrefixes = setOf(
        "146.112.", "128.121.", "67.215.", "204.232.", "198.18."
    )

    fun onNetworkChanged() {
        ipRtt.clear()
        dnsCache.entries.removeIf { it.value.second - System.currentTimeMillis() < CACHE_TTL_MS / 2 }
        Log.d("DnsCache", "Network change detected, optimized DNS cache")
    }

    fun clearAll() {
        dnsCache.clear()
        detailedDnsCache.clear()
        echSupportCache.clear()
        ipHeatmap.clear()
        ipRtt.clear()
        negativeCache.clear()
        resolverBlacklist.clear()
    }

    fun ensureEfficiency() {
        val now = System.currentTimeMillis()
        if (ipHeatmap.size > 1500) {
            ipHeatmap.entries.removeIf { it.value < 20 }
            if (ipHeatmap.size > 2000) ipHeatmap.clear()
        }
        if (dnsCache.size > MAX_DNS_CACHE_SIZE) {
            dnsCache.entries.removeIf { it.value.second < now }
            if (dnsCache.size > MAX_DNS_CACHE_SIZE) dnsCache.clear()
        }
        if (detailedDnsCache.size > MAX_DNS_CACHE_SIZE) {
            detailedDnsCache.entries.removeIf { it.value.second < now }
            if (detailedDnsCache.size > MAX_DNS_CACHE_SIZE) detailedDnsCache.clear()
        }
        if (negativeCache.size > 500) {
            negativeCache.entries.removeIf { now - it.value > NEGATIVE_CACHE_TTL }
            if (negativeCache.size > 1000) negativeCache.clear()
        }
        if (ipRtt.size > 2000) ipRtt.clear()
        if (resolverBlacklist.size > 100) resolverBlacklist.entries.removeIf { now > it.value }
        if (resolverSuccess.size > 500) resolverSuccess.clear()
        if (resolverFailure.size > 500) resolverFailure.clear()
    }

    fun getCached(host: String, type: Int = 1): List<InetAddress>? {
        ensureEfficiency()
        if (isIpAddress(host)) {
            return try { listOf(InetAddress.getByName(host)) } catch (e: Exception) { null }
        }
        val cacheKey = if (type == 1) host else "$host:$type"
        val now = System.currentTimeMillis()
        dnsCache[cacheKey]?.let { (addresses, expiry) ->
            if (now < expiry) {
                // If cache is about to expire (in <20% of TTL), trigger background refresh early
                if (expiry - now < CACHE_TTL_MS / 5) {
                    val scope = VpnSessionManager.currentSession?.dnsScope ?: ProxyDispatcher.globalScope
                    scope.launch {
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
    }

    fun getCachedOrStale(host: String, type: Int = 1, maxStaleMs: Long = 24 * 3600 * 1000L): List<InetAddress>? {
        ensureEfficiency()
        if (isIpAddress(host)) {
            return try { listOf(InetAddress.getByName(host)) } catch (e: Exception) { null }
        }
        val cacheKey = if (type == 1) host else "$host:$type"
        val now = System.currentTimeMillis()
        dnsCache[cacheKey]?.let { (addresses, expiry) ->
            if (now < expiry + maxStaleMs) {
                // Stale-While-Revalidate: Return stale cached IPs immediately, and trigger async background update
                val scope = VpnSessionManager.currentSession?.dnsScope ?: ProxyDispatcher.globalScope
                scope.launch {
                    try {
                        RobustResolver.resolve(host, null, type)
                    } catch (e: Exception) {}
                }
                return getSortedIps(addresses)
            }
        }
        return getEmergencyFallback(host)
    }


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



    fun putDetailed(host: String, records: List<DnsPacketEngine.DnsRecord>, type: Int = 1) {
        if (records.isEmpty()) return
        val addresses = records.map { it.address }
        val minTtl = records.minOf { it.ttlSeconds }.coerceIn(30, 3600) * 1000L
        val expiry = System.currentTimeMillis() + minTtl
        put(host, addresses, minTtl, type)
        val cacheKey = if (type == 1) host else "$host:$type"
        detailedDnsCache[cacheKey] = records to expiry
    }

    fun getEmergencyFallback(host: String): List<InetAddress>? {
        val lHost = host.lowercase()
        for ((domain, ips) in emergencyFallback) {
            if (lHost == domain || lHost.endsWith(".$domain")) {
                return ips.mapNotNull { try { InetAddress.getByName(it) } catch (e: Exception) { null } }
            }
        }
        return null
    }

    fun recordIpSuccess(ip: String, rtt: Long = 0) {
        val current = ipHeatmap.getOrDefault(ip, 50)
        ipHeatmap[ip] = (current + 8).coerceAtMost(100)
        if (rtt > 0) {
            val oldRtt = ipRtt.getOrDefault(ip, rtt)
            ipRtt[ip] = (oldRtt * 0.6 + rtt * 0.4).toLong()
        }
    }

    fun recordIpFailure(ip: String) {
        val current = ipHeatmap.getOrDefault(ip, 50)
        val newVal = (current - 15).coerceAtLeast(0)
        ipHeatmap[ip] = newVal
        if (newVal == 0 && !ip.startsWith("192.168.") && !ip.startsWith("10.")) {
            poisonedIps.add(ip)
        }
    }

    fun putNegative(host: String, ttlMs: Long = NEGATIVE_CACHE_TTL) {
        negativeCache[host] = System.currentTimeMillis() + ttlMs
    }

    fun isNegative(host: String): Boolean {
        val expiry = negativeCache[host] ?: return false
        if (System.currentTimeMillis() > expiry) {
            negativeCache.remove(host)
            return false
        }
        return true
    }

    fun reportResolverResult(provider: String, success: Boolean) {
        if (success) {
            resolverSuccess[provider] = (resolverSuccess[provider] ?: 0) + 1
            val f = resolverFailure[provider] ?: 0
            if (f > 0) resolverFailure[provider] = f - 1
        } else {
            val f = (resolverFailure[provider] ?: 0) + 1
            resolverFailure[provider] = f
            if (f > 3) resolverBlacklist[provider] = System.currentTimeMillis() + 300000L
        }
    }

    fun isResolverOk(provider: String): Boolean {
        val expiry = resolverBlacklist[provider] ?: return true
        if (System.currentTimeMillis() > expiry) {
            resolverBlacklist.remove(provider)
            return true
        }
        return false
    }

    fun isPoisoned(address: InetAddress, host: String): Boolean {
        val ip = address.hostAddress ?: return true
        if (poisonedIps.contains(ip)) return true
        if (address.isLoopbackAddress || ip == "0.0.0.0") return true
        if (!host.endsWith(".local") && !host.contains("localhost")) {
            if (ip.startsWith("10.") || ip.startsWith("127.")) return true
            if (poisonedPrefixes.any { ip.startsWith(it) }) return true
        }
        return false
    }

    fun isSuspicious(host: String, ips: List<InetAddress>): Boolean {
        if (ips.isEmpty()) return false
        val ipStrs = ips.map { it.hostAddress ?: "" }
        if (ipStrs.any { it in bogonIps && host != "dns.google" }) return true
        return ips.any { it.isSiteLocalAddress || it.isLoopbackAddress }
    }

    fun getSortedIps(ips: List<InetAddress>): List<InetAddress> {
        val preferIpv6 = BypassConfig.preferIpv6
        return ips.sortedWith(compareByDescending<InetAddress> { 
            ipHeatmap.getOrDefault(it.hostAddress ?: "", 50) 
        }.thenBy {
            ipRtt.getOrDefault(it.hostAddress ?: "", 200L)
        }.thenByDescending { 
            if (preferIpv6) it is Inet6Address else it !is Inet6Address
        })
    }

    fun isIpAddress(host: String): Boolean = host.matches(Regex("""^(\d{1,3}\.){3}\d{1,3}$""")) || host.contains(":")

    fun save(context: android.content.Context) {
        try {
            val prefs = context.getSharedPreferences("pink_dns_cache_prefs", android.content.Context.MODE_PRIVATE)
            val now = System.currentTimeMillis()
            val jsonArr = org.json.JSONArray()
            dnsCache.forEach { (key, pair) ->
                if (pair.second > now) {
                    val obj = org.json.JSONObject()
                    obj.put("key", key)
                    val ipsArr = org.json.JSONArray()
                    pair.first.forEach { ipsArr.put(it.hostAddress) }
                    obj.put("ips", ipsArr)
                    obj.put("exp", pair.second)
                    jsonArr.put(obj)
                }
            }
            prefs.edit().putString("cache_data", jsonArr.toString()).apply()
        } catch (e: Exception) {
            Log.w("DnsCacheManager", "Failed to save DNS cache: ${e.message}")
        }
    }

    fun load(context: android.content.Context) {
        try {
            val prefs = context.getSharedPreferences("pink_dns_cache_prefs", android.content.Context.MODE_PRIVATE)
            val data = prefs.getString("cache_data", null) ?: return
            val jsonArr = org.json.JSONArray(data)
            val now = System.currentTimeMillis()
            for (i in 0 until jsonArr.length()) {
                val obj = jsonArr.getJSONObject(i)
                val exp = obj.getLong("exp")
                if (exp > now) {
                    val key = obj.getString("key")
                    val ipsArr = obj.getJSONArray("ips")
                    val list = mutableListOf<InetAddress>()
                    for (j in 0 until ipsArr.length()) {
                        try {
                            val ipStr = ipsArr.getString(j)
                            if (ipStr != null) {
                                list.add(InetAddress.getByName(ipStr))
                            }
                        } catch (ignored: Exception) {}
                    }
                    if (list.isNotEmpty()) {
                        dnsCache[key] = Pair(list, exp)
                    }
                }
            }
        } catch (e: Exception) {
            Log.w("DnsCacheManager", "Failed to load DNS cache: ${e.message}")
        }
    }
    fun clear() = clearAll()

    fun ageHeatmap() {
        val intensity = BypassConfig.getIntensityForTransport(com.aistudio.pinkproxy.fresh.TransportType.DNS)
        val decay = if (intensity > 80) 0.99f else 0.96f
        val iterator = ipHeatmap.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            val score = entry.value
            if (score < 100) {
                val newScore = (score * decay).toInt()
                if (newScore < 5) iterator.remove()
                else entry.setValue(newScore)
            }
        }
    }

    fun clearExpired() {
        val now = System.currentTimeMillis()
        dnsCache.entries.removeIf { now > it.value.second }
        negativeCache.entries.removeIf { now > it.value }
    }

    fun getStaticIps(host: String): List<InetAddress>? {
        return staticIps[host]?.mapNotNull { 
            try { InetAddress.getByName(it) } catch (e: Exception) { null }
        }
    }

    fun getDynamicTtl(): Long {
        val intensity = BypassConfig.getIntensityForTransport(com.aistudio.pinkproxy.fresh.TransportType.DNS)
        return if (intensity > 80) 3600 * 1000L else if (intensity > 50) 1800 * 1000L else CACHE_TTL_MS
    }

    fun putEchSupport(host: String, supported: Boolean) {
        echSupportCache[host] = supported
        if (echSupportCache.size > MAX_DNS_CACHE_SIZE) echSupportCache.clear()
    }

    fun isEchSupported(host: String): Boolean = echSupportCache[host] ?: false
}
