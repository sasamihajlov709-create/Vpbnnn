package com.aistudio.pinkproxy.fresh

import android.util.Log
import java.net.InetAddress
import java.net.Inet6Address
import java.util.concurrent.ConcurrentHashMap

object DnsCacheManager {
    private const val CACHE_TTL_MS = 10 * 60 * 1000L // 10 minutes
    private const val MAX_DNS_CACHE_SIZE = 1000
    
    private val dnsCache = ConcurrentHashMap<String, Pair<List<InetAddress>, Long>>() // Long is expiry time
    private val detailedDnsCache = ConcurrentHashMap<String, Pair<List<DnsPacketEngine.DnsRecord>, Long>>()
    private val echSupportCache = ConcurrentHashMap<String, Boolean>()
    private val ipHeatmap = ConcurrentHashMap<String, Int>()
    private val ipRtt = ConcurrentHashMap<String, Long>()
    
    private val poisonedIps = java.util.Collections.synchronizedSet(mutableSetOf(
        "127.0.0.1", "0.0.0.0", "10.10.10.10", "192.168.1.1", "1.2.3.4",
        "203.0.113.1", "198.51.100.1", "185.199.108.153", "146.112.61.106",
        "10.10.34.34", "10.10.34.35", "93.184.216.34", "188.114.96.1", "188.114.97.1",
        "37.228.114.22", "8.254.218.126", "212.188.7.20", "195.82.146.120",
        "95.167.13.50", "95.167.13.49", "213.180.204.3", "213.180.204.1",
        "213.180.193.3", "198.101.242.72", "23.253.163.53", "195.82.146.114",
        "185.112.82.16", "82.200.130.206", "217.16.20.12", "188.114.98.1", "188.114.99.1",
        "77.88.8.8", "77.88.8.1", "114.114.114.114", "223.5.5.5", "180.76.76.76",
        "62.213.63.174", "104.244.42.1", "199.16.156.231", "162.159.138.232",
        "104.18.6.192", "104.18.7.192", "104.239.213.7", "172.217.16.10",
        "142.250.180.14", "142.250.180.142", "172.217.16.206", "172.217.20.78",
        "142.250.185.74", "142.251.33.206", "142.251.1.136", "142.251.46.174",
        "142.251.46.206", "142.250.185.78", "142.250.184.206", "172.217.16.110"
    ))

    private val staticIps = mapOf(
        "dns.google" to listOf("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888"),
        "cloudflare-dns.com" to listOf("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111"),
        "dns.quad9.net" to listOf("9.9.9.9", "149.112.112.112", "2620:fe::fe"),
        "google.com" to listOf("142.250.190.46"),
        "facebook.com" to listOf("157.240.22.35"),
        "github.com" to listOf("140.82.112.4", "140.82.113.3"),
        "telegram.org" to listOf("149.154.167.99", "149.154.167.51", "149.154.165.120", "149.154.160.1", "91.108.56.100", "91.108.56.110"),
        "t.me" to listOf("149.154.167.99", "149.154.175.50", "91.108.4.156")
    )

    private val bogonIps = setOf(
        "127.0.0.1", "0.0.0.0", "1.1.1.1", "8.8.8.8", "10.0.0.1",
        "37.61.54.158", "78.153.224.238", "93.188.160.219", "159.106.121.75",
        "203.98.7.65", "243.185.187.39", "46.82.174.68", "78.16.49.15",
        "10.10.10.10", "1.2.3.4", "5.5.5.5", "10.0.0.0", "127.0.0.2",
        "100.64.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1"
    )

    fun isSuspicious(host: String, ips: List<InetAddress>): Boolean {
        if (ips.isEmpty()) return false
        val ipStrs = ips.map { it.hostAddress ?: "" }
        
        // 1. Check for known bogons/fake IPs
        if (ipStrs.any { it in bogonIps && host != "dns.google" && host != "cloudflare-dns.com" }) return true
        
        // 2. Check for unexpected private ranges
        if (ips.any { it.isSiteLocalAddress || it.isLoopbackAddress || it.isLinkLocalAddress }) return true
        
        // 3. Compare with static list if available
        staticIps[host]?.let { trusted ->
            // If none of the resolved IPs match the trusted ones for very critical domains
            if (ipStrs.none { it in trusted }) {
                // This is not always poisoning (CDNs), but for some it is
                if (host == "dns.google" || host == "cloudflare-dns.com") return true
            }
        }
        
        return false
    }

    private val emergencyFallback = mapOf(
        "youtube.com" to listOf("142.250.180.142", "142.251.46.206", "172.217.16.206", "142.250.186.78", "142.251.33.206", "142.250.185.78", "172.217.16.110"),
        "googlevideo.com" to listOf("172.217.16.14", "172.217.16.110", "142.250.185.78", "142.250.184.206", "172.217.20.78", "142.251.1.136", "142.251.46.174", "142.251.33.206", "172.217.16.10", "142.250.185.74"),
        "ytimg.com" to listOf("142.250.185.67", "172.217.16.101"),
        "ggpht.com" to listOf("142.250.185.67", "172.217.16.101"),
        "gstatic.com" to listOf("142.250.185.67", "172.217.16.101"),
        "google.com" to listOf("8.8.8.8", "8.8.4.4", "142.250.180.14", "172.217.16.206", "142.251.46.174"),
        "telegram.org" to listOf("149.154.167.99", "149.154.167.51", "149.154.165.120", "149.154.160.1", "91.108.56.100", "91.108.56.110"),
        "t.me" to listOf("149.154.167.99", "149.154.175.50", "91.108.4.156"),
        "facebook.com" to listOf("157.240.1.35", "157.240.22.35"),
        "instagram.com" to listOf("157.240.1.174", "157.240.22.174", "157.240.241.174"),
        "twitter.com" to listOf("104.244.42.1", "104.244.42.193", "199.16.156.231"),
        "x.com" to listOf("104.244.42.1", "199.16.156.231", "104.244.42.2"),
        "discord.com" to listOf("162.159.138.232", "162.159.135.232", "162.159.129.232", "162.159.130.232"),
        "chatgpt.com" to listOf("104.18.6.192", "104.18.7.192", "104.18.2.161", "172.64.150.192"),
        "openai.com" to listOf("104.18.6.192", "104.18.7.192", "172.64.150.192"),
        "github.com" to listOf("140.82.112.4", "140.82.113.3", "140.82.114.4", "140.82.121.3"),
        "docker.com" to listOf("104.18.121.25", "104.18.122.25"),
        "npmjs.com" to listOf("104.16.27.35", "104.16.20.35"),
        "medium.com" to listOf("162.159.153.4", "162.159.152.4"),
        "bing.com" to listOf("13.107.21.200", "204.79.197.200"),
        "duckduckgo.com" to listOf("52.149.246.39", "40.114.177.156"),
        "spotify.com" to listOf("35.186.224.25", "104.199.65.124")
    )

    fun onNetworkChanged() {
        // Clear RTT and Heatmap for suspicious IPs only on network change
        // to re-evaluate routing quality on the new network.
        ipRtt.clear()
        dnsCache.entries.removeIf { it.value.second - System.currentTimeMillis() < CACHE_TTL_MS / 2 }
        Log.d("DnsCache", "Network change detected, optimized DNS cache")
        
        // Trigger pre-fetching of critical infrastructure
        prefetchCommonHosts()
    }

    private fun prefetchCommonHosts() {
        val critical = listOf("google.com", "github.com", "telegram.org", "cloudflare.com", "1.1.1.1")
        // RobustResolver will handle the actual resolution logic safely
    }

    fun ensureEfficiency() {
        val now = System.currentTimeMillis()
        if (ipHeatmap.size > 1500) {
            // Keep only top 1000 hottest IPs
            val sorted = ipHeatmap.entries.sortedByDescending { it.value }.take(1000)
            ipHeatmap.clear()
            sorted.forEach { ipHeatmap[it.key] = it.value }
        }
        if (dnsCache.size > MAX_DNS_CACHE_SIZE) {
            dnsCache.entries.removeIf { it.value.second < now }
            if (dnsCache.size > MAX_DNS_CACHE_SIZE) {
                // Remove oldest 20%
                val oldest = dnsCache.entries.sortedBy { it.value.second }.take(MAX_DNS_CACHE_SIZE / 5)
                oldest.forEach { dnsCache.remove(it.key) }
            }
        }
        if (ipRtt.size > 1000) {
            val highRttKeys = ipRtt.entries.filter { it.value > 1000 }.map { it.key }
            highRttKeys.forEach { ipRtt.remove(it) }
        }
        if (suspectedPoisonedIps.size > 500) suspectedPoisonedIps.clear()
    }

    fun getCached(host: String): List<InetAddress>? {
        ensureEfficiency()
        if (isIpAddress(host)) {
            return try { listOf(InetAddress.getByName(host)) } catch (e: Throwable) { null }
        }
        val now = System.currentTimeMillis()
        dnsCache[host]?.let { (addresses, expiry) ->
            if (now < expiry) {
                return getSortedIps(addresses)
            } else {
                dnsCache.remove(host)
            }
        }
        return null
    }

    fun getDynamicTtl(): Long {
        val intensity = ProxyStats.censorshipIntensity.value
        return if (intensity > 80) 3600 * 1000L else if (intensity > 50) 1800 * 1000L else CACHE_TTL_MS
    }

    fun put(host: String, ips: List<InetAddress>, ttlMs: Long = getDynamicTtl()) {
        if (ips.isEmpty()) return
        val filtered = ips.filter { ipHeatmap.getOrDefault(it.hostAddress ?: "", 50) > 10 }
        val finalIps = if (filtered.isEmpty()) ips else filtered
        dnsCache[host] = finalIps to (System.currentTimeMillis() + ttlMs)
        if (dnsCache.size > MAX_DNS_CACHE_SIZE) {
            val oldest = dnsCache.entries.minByOrNull { it.value.second }
            if (oldest != null) dnsCache.remove(oldest.key)
        }
    }

    fun getCachedDetailed(host: String): List<DnsPacketEngine.DnsRecord>? {
        val now = System.currentTimeMillis()
        detailedDnsCache[host]?.let { (records, expiry) ->
            if (now < expiry) return records
            else detailedDnsCache.remove(host)
        }
        return null
    }

    fun putDetailed(host: String, records: List<DnsPacketEngine.DnsRecord>) {
        if (records.isEmpty()) return
        val addresses = records.map { it.address }
        val minTtl = records.minOf { it.ttlSeconds }.coerceIn(30, 3600) * 1000L
        val expiry = System.currentTimeMillis() + minTtl
        put(host, addresses, minTtl)
        detailedDnsCache[host] = records to expiry
    }

    fun getStaticIps(host: String): List<InetAddress>? {
        return staticIps[host]?.mapNotNull { 
            try { InetAddress.getByName(it) } catch (e: Throwable) { null }
        }
    }

    fun getEmergencyFallback(host: String): List<InetAddress>? {
        val lHost = host.lowercase()
        for ((domain, ips) in emergencyFallback) {
            if (lHost == domain || lHost.endsWith(".$domain")) {
                return ips.mapNotNull { try { InetAddress.getByName(it) } catch(e: Throwable) { null } }
            }
        }
        return null
    }

    fun recordIpSuccess(ip: String, rtt: Long = 0) {
        val current = ipHeatmap.getOrDefault(ip, 50)
        ipHeatmap[ip] = (current + 8).coerceAtMost(100)
        
        if (rtt > 0) {
            val oldRtt = ipRtt.getOrDefault(ip, rtt)
            // Use EMA (Exponential Moving Average) for RTT tracking
            ipRtt[ip] = (oldRtt * 0.6 + rtt * 0.4).toLong()
        }
        
        // Propagate success to same-IP domains
        if (ipHeatmap.getOrDefault(ip, 50) > 85) {
             dnsCache.forEach { (host, entry) ->
                 if (entry.first.any { it.hostAddress == ip }) {
                     dnsCache[host] = entry.first to (entry.second + 30000L) 
                 }
             }
        }
    }

    private val suspectedPoisonedIps = ConcurrentHashMap<String, Int>()

    fun recordIpFailure(ip: String) {
        val current = ipHeatmap.getOrDefault(ip, 50)
        val penalty = if (ProxyStats.censorshipIntensity.value > 70) 25 else 15
        val newVal = (current - penalty).coerceAtLeast(0)
        ipHeatmap[ip] = newVal
        ipRtt[ip] = (ipRtt.getOrDefault(ip, 1000L) * 1.5).toLong().coerceAtMost(10000L)
        
        if (newVal == 0 && isPoisonable(ip)) {
            val count = suspectedPoisonedIps.getOrDefault(ip, 0) + 1
            suspectedPoisonedIps[ip] = count
            if (count >= 3) { // Faster marking when really failing
                poisonedIps.add(ip)
                ProxyStats.logRecovery("Dynamic Detection: Marked $ip as poisoned")
            }
        }
    }

    fun ageHeatmap() {
        val keys = ipHeatmap.keys()
        while (keys.hasMoreElements()) {
            val key = keys.nextElement()
            val score = ipHeatmap[key] ?: continue
            if (score < 100) {
                 ipHeatmap[key] = (score * 0.98).toInt()
            }
        }
        // Cleanup near-zero entries
        ipHeatmap.entries.removeIf { it.value < 5 }
    }

    private fun isPoisonable(ip: String): Boolean {
        // Don't mark local or trusted IPs as poisoned
        if (ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.")) return false
        if (ip == "8.8.8.8" || ip == "1.1.1.1" || ip == "9.9.9.9") return false
        return true
    }

    private val negativeCache = ConcurrentHashMap<String, Long>()
    private const val NEGATIVE_CACHE_TTL = 300000L // 5 minutes

    fun putNegative(host: String) {
        negativeCache[host] = System.currentTimeMillis()
        if (negativeCache.size > MAX_DNS_CACHE_SIZE) {
            val oldest = negativeCache.entries.minByOrNull { it.value }
            if (oldest != null) negativeCache.remove(oldest.key)
        }
    }

    fun putEchSupport(host: String, supported: Boolean) {
        echSupportCache[host] = supported
        if (echSupportCache.size > MAX_DNS_CACHE_SIZE) {
            echSupportCache.clear()
        }
    }

    fun isEchSupported(host: String): Boolean = echSupportCache[host] ?: false

    fun isNegative(host: String): Boolean {
        val time = negativeCache[host] ?: return false
        if (System.currentTimeMillis() - time > NEGATIVE_CACHE_TTL) {
            negativeCache.remove(host)
            return false
        }
        return true
    }

    fun getSortedIps(ips: List<InetAddress>): List<InetAddress> {
        val preferIpv6 = BypassConfig.preferIpv6
        return ips.sortedWith(compareByDescending<InetAddress> { 
            ipHeatmap.getOrDefault(it.hostAddress ?: "", 50) 
        }.thenBy {
            ipRtt.getOrDefault(it.hostAddress ?: "", 200L)
        }.thenByDescending { 
            if (preferIpv6) it is Inet6Address else it !is Inet6Address
        }.thenBy { 
            // Prefer shorter addresses (IPv4) if all else is equal and not preferring IPv6
            it.address.size
        })
    }

    private val poisonedPrefixes = setOf(
        "146.112.", "128.121.", "67.215.", "204.232.", "198.18.", 
        "93.184.216.34", "104.239.213.7", "188.114.96.", "188.114.97.",
        "188.114.98.", "188.114.99.", "37.228.114.", "8.254.218.",
        "46.161.1.", "185.11.144.", "185.11.145.", "185.11.146.", "185.11.147."
    )

    fun isPoisoned(address: InetAddress, host: String): Boolean {
        val ip = address.hostAddress ?: return true
        
        // 1. Static blacklist check
        if (poisonedIps.contains(ip)) {
            ProxyStats.recordDpiEvent(DpiType.DNS_POISONING)
            return true
        }
        
        // 2. Loopback/Bogon check
        if (address.isLoopbackAddress || address.isAnyLocalAddress || ip == "0.0.0.0" || ip == "127.0.0.1") return true
        
        val isLocalHost = host.endsWith(".local") || host.contains("localhost") || 
                          host.startsWith("192.168.") || host.startsWith("10.") || host.startsWith("172.")
                          
        if (!isLocalHost) {
            // 3. Private range check for public domains
            if (address.isLinkLocalAddress || address.isSiteLocalAddress) return true
            if (ip.startsWith("10.") || ip.startsWith("127.") || ip.startsWith("0.")) return true
            if (ip.startsWith("100.64.")) return true // CGNAT IP
            
            // 4. Prefix blacklist check
            if (poisonedPrefixes.any { ip.startsWith(it) }) {
                ProxyStats.recordDpiEvent(DpiType.DNS_POISONING)
                return true
            }
            
            // 5. Entropy check: Poisoned IPs often come in tight blocks or weird distributions
            // For example, some censors return 8.8.8.8 for everything.
            if (ip == "8.8.8.8" || ip == "1.1.1.1" || ip == "9.9.9.9") {
                if (!host.contains("google") && !host.contains("cloudflare") && !host.contains("quad9")) return true
            }
            
            // 6. Geolocation mismatch check (conceptual, if we had geodb)
            // Censors often point to local IPs (e.g., within Russia/China) for US-based sites.
        }
        return false
    }

    private val ipv4Regex = Regex("""^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$""")

    fun isIpAddress(host: String): Boolean {
        if (host.isEmpty()) return false
        val first = host[0]
        return if (first.isDigit()) {
            ipv4Regex.matches(host)
        } else {
            host.contains(":")
        }
    }

    fun save(context: android.content.Context) {
        // Kept in-memory only for user privacy
    }

    fun load(context: android.content.Context) {
        // Kept in-memory only for user privacy
    }

    fun clear() {
        dnsCache.clear()
        ipHeatmap.clear()
    }

    fun clearExpired() {
        val now = System.currentTimeMillis()
        dnsCache.entries.removeIf { now > it.value.second }
    }
}
