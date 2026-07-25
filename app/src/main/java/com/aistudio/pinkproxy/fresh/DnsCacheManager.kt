package com.aistudio.pinkproxy.fresh

import android.util.Log
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

object DnsCacheManager {
    private const val CACHE_TTL_MS = 10 * 60 * 1000L // 10 minutes
    private const val MAX_DNS_CACHE_SIZE = 1000
    
    private val dnsCache = ConcurrentHashMap<String, Pair<List<InetAddress>, Long>>()
    private val ipHeatmap = ConcurrentHashMap<String, Int>()
    
    private val poisonedIps = java.util.Collections.synchronizedSet(mutableSetOf(
        "127.0.0.1", "0.0.0.0", "10.10.10.10", "192.168.1.1", "1.2.3.4",
        "203.0.113.1", "198.51.100.1", "185.199.108.153", "146.112.61.106",
        "10.10.34.34", "10.10.34.35", "93.184.216.34", "188.114.96.1", "188.114.97.1",
        "37.228.114.22", "8.254.218.126", "212.188.7.20", "195.82.146.120",
        "95.167.13.50", "95.167.13.49", "213.180.204.3", "213.180.204.1",
        "213.180.193.3", "198.101.242.72", "23.253.163.53", "195.82.146.114",
        "185.112.82.16", "82.200.130.206", "217.16.20.12"
    ))

    private val staticIps = mapOf(
        "dns.google" to listOf("8.8.8.8", "8.8.4.4"),
        "cloudflare-dns.com" to listOf("1.1.1.1", "1.0.0.1"),
        "dns.quad9.net" to listOf("9.9.9.9", "149.112.112.112"),
        "google.com" to listOf("142.250.190.46"),
        "facebook.com" to listOf("157.240.22.35")
    )

    private val emergencyFallback = mapOf(
        "youtube.com" to listOf("142.250.180.142", "142.251.46.206", "172.217.16.206", "142.250.186.78"),
        "googlevideo.com" to listOf("172.217.16.14", "172.217.16.110", "142.250.185.78", "142.250.184.206"),
        "google.com" to listOf("8.8.8.8", "8.8.4.4", "142.250.180.14"),
        "telegram.org" to listOf("149.154.167.99", "149.154.167.51", "149.154.165.120", "149.154.160.1"),
        "t.me" to listOf("149.154.167.99", "149.154.175.50"),
        "facebook.com" to listOf("157.240.1.35", "157.240.22.35"),
        "instagram.com" to listOf("157.240.1.174", "157.240.22.174"),
        "twitter.com" to listOf("104.244.42.1", "104.244.42.193"),
        "x.com" to listOf("104.244.42.1", "199.16.156.231"),
        "discord.com" to listOf("162.159.138.232", "162.159.135.232"),
        "chatgpt.com" to listOf("104.18.6.192", "104.18.7.192", "104.18.2.161"),
        "openai.com" to listOf("104.18.6.192", "104.18.7.192")
    )

    fun getCached(host: String): List<InetAddress>? {
        if (isIpAddress(host)) {
            return try { listOf(InetAddress.getByName(host)) } catch (e: Exception) { null }
        }
        val now = System.currentTimeMillis()
        dnsCache[host]?.let { (addresses, timestamp) ->
            if (now - timestamp < CACHE_TTL_MS) {
                return getSortedIps(addresses)
            }
        }
        return null
    }

    fun put(host: String, ips: List<InetAddress>) {
        if (ips.isEmpty()) return
        dnsCache[host] = ips to System.currentTimeMillis()
        if (dnsCache.size > MAX_DNS_CACHE_SIZE) {
            val oldest = dnsCache.entries.minByOrNull { it.value.second }
            if (oldest != null) dnsCache.remove(oldest.key)
        }
    }

    fun getStaticIps(host: String): List<InetAddress>? {
        return staticIps[host]?.mapNotNull { 
            try { InetAddress.getByName(it) } catch (e: Exception) { null }
        }
    }

    fun getEmergencyFallback(host: String): List<InetAddress>? {
        val lHost = host.lowercase()
        for ((domain, ips) in emergencyFallback) {
            if (lHost == domain || lHost.endsWith(".$domain")) {
                return ips.mapNotNull { try { InetAddress.getByName(it) } catch(e: Exception) { null } }
            }
        }
        return null
    }

    fun recordIpSuccess(ip: String) {
        val current = ipHeatmap.getOrDefault(ip, 50)
        ipHeatmap[ip] = (current + 5).coerceAtMost(100)
    }

    fun recordIpFailure(ip: String) {
        val current = ipHeatmap.getOrDefault(ip, 50)
        ipHeatmap[ip] = (current - 15).coerceAtLeast(0)
    }

    fun getSortedIps(ips: List<InetAddress>): List<InetAddress> {
        return ips.sortedByDescending { ipHeatmap.getOrDefault(it.hostAddress ?: "", 50) }
    }

    fun isPoisoned(address: InetAddress, host: String): Boolean {
        val ip = address.hostAddress ?: return true
        if (poisonedIps.contains(ip)) return true
        if (address.isLoopbackAddress || address.isAnyLocalAddress) return true
        
        val isLocalHost = host.endsWith(".local") || host.contains("localhost") || 
                          host.startsWith("192.168.") || host.startsWith("10.") || host.startsWith("172.")
                          
        if (!isLocalHost) {
            if (address.isLinkLocalAddress || address.isSiteLocalAddress) return true
            if (ip.startsWith("10.") || ip.startsWith("127.") || ip.startsWith("0.")) return true
            
            val poisonedPrefixes = listOf(
                "146.112.", "128.121.", "67.215.", "204.232.", "198.18.", 
                "93.184.216.34", "104.239.213.7"
            )
            if (poisonedPrefixes.any { ip.startsWith(it) }) return true
        }
        return false
    }

    fun isIpAddress(host: String): Boolean {
        return host.matches(Regex("""^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$""")) || host.contains(":")
    }

    fun clear() {
        dnsCache.clear()
        ipHeatmap.clear()
    }

    fun clearExpired() {
        val now = System.currentTimeMillis()
        dnsCache.entries.removeIf { now - it.value.second > CACHE_TTL_MS }
    }
}
