package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import java.util.concurrent.ConcurrentHashMap

object DnsOptimizer {
    private val dohUrls = listOf(
        "https://dns.google/dns-query",
        "https://cloudflare-dns.com/dns-query",
        "https://dns.quad9.net/dns-query",
        "https://dns.adguard-dns.com/dns-query",
        "https://doh.opendns.com/dns-query",
        "https://doh.mullvad.net/dns-query",
        "https://dns.nextdns.io/dns-query",
        "https://dns.controld.com/dns-query",
        "https://dns.google/dns-query?source=pink",
        "https://1.1.1.1/dns-query",
        "https://doh.libredns.gr/dns-query",
        "https://doh.tiar.app/dns-query",
        "https://dns.switch.ch/dns-query",
        "https://doh.cleanbrowsing.org/doh/family-filter/",
        "https://doh.pub/dns-query",
        "https://dns.alidns.com/dns-query",
        "https://doh.powerdns.org",
        "https://doh.applied-privacy.net/query",
        "https://dns.google/resolve",
        "https://dns11.quad9.net/dns-query",
        "https://doh.mullvad.net/dns-query",
        "https://dns.google/dns-query?source=android",
        "https://1.0.0.1/dns-query",
        "https://doh.opendns.com/dns-query",
        "https://doh.xfinity.com/dns-query",
        "https://doh.ff.avast.com/dns-query"
    )
    
    private val dotServers = listOf("8.8.8.8", "1.1.1.1", "9.9.9.9", "94.140.14.14", "45.90.28.0", "185.228.168.9", "76.76.2.0")

    private val providerLatencies = ConcurrentHashMap<String, Long>()
    private val providerFailures = ConcurrentHashMap<String, Int>()
    @Volatile var bestDohUrl = "https://dns.google/dns-query"
    @Volatile var bestDotServer = "8.8.8.8"
    
    fun getDohUrls(): List<String> {
        // Return sorted by performance
        return dohUrls.sortedBy { (providerLatencies[it] ?: 500L) + (providerFailures[it] ?: 0) * 100L }
    }
    
    fun recordDohSuccess(url: String) {
        providerFailures[url] = (providerFailures[url] ?: 1) - 1
        if (providerFailures[url]!! < 0) providerFailures[url] = 0
    }
    
    fun recordDohFailure(url: String) {
        providerFailures[url] = (providerFailures[url] ?: 0) + 1
    }
    fun getDotServers() = dotServers

    private val criticalDomains = listOf(
        "youtube.com", "googlevideo.com", "google.com", "t.me", "telegram.org",
        "instagram.com", "twitter.com", "x.com", "discord.com", "chatgpt.com",
        "openai.com", "netflix.com", "facebook.com", "googleusercontent.com",
        "gstatic.com", "googleapis.com", "apple.com", "icloud.com"
    )

    fun forceRefresh() {
        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        start(scope, null)
    }

    fun start(scope: CoroutineScope, vpnService: VpnService?) {
        // Immediate Warm-up phase
        scope.launch(Dispatchers.IO) {
            Log.i("DnsOptimizer", "Starting DNS Warm-up...")
            criticalDomains.map { domain ->
                async {
                    try {
                        val ips = RobustResolver.resolve(domain, vpnService)
                        if (ips.isNotEmpty()) DnsCacheManager.put(domain, ips)
                    } catch (e: Exception) {}
                }
            }.awaitAll()
            Log.i("DnsOptimizer", "DNS Warm-up completed.")
        }

        // Latency Prober
        scope.launch(Dispatchers.IO) {
            while (isActive) {
                val dohJobs = dohUrls.map { url ->
                    async {
                        val start = System.currentTimeMillis()
                        val res = DnsProtocols.queryDoh("google.com", url, vpnService)
                        if (res.isNotEmpty()) {
                            providerLatencies[url] = System.currentTimeMillis() - start
                        } else {
                            providerLatencies[url] = 9999L
                        }
                    }
                }
                val dotJobs = dotServers.map { server ->
                    async {
                        val start = System.currentTimeMillis()
                        val res = DnsProtocols.queryDot("google.com", server, vpnService)
                        if (res.isNotEmpty()) {
                            providerLatencies[server] = System.currentTimeMillis() - start
                        } else {
                            providerLatencies[server] = 9999L
                        }
                    }
                }
                dohJobs.awaitAll()
                dotJobs.awaitAll()
                
                bestDohUrl = providerLatencies.filterKeys { it.startsWith("https") }.minByOrNull { it.value }?.key ?: dohUrls[0]
                bestDotServer = providerLatencies.filterKeys { !it.startsWith("https") }.minByOrNull { it.value }?.key ?: dotServers[0]
                
                delay(10 * 60 * 1000L) // Every 10 min
            }
        }

        // Prefetcher
        scope.launch(Dispatchers.IO) {
            while (isActive) {
                delay(15 * 60 * 1000L)
                criticalDomains.map { domain ->
                    async {
                        try {
                            RobustResolver.resolve(domain, vpnService)
                        } catch (e: Exception) {}
                    }
                }.awaitAll()
            }
        }

        // Self-Healing
        scope.launch(Dispatchers.IO) {
            while (isActive) {
                delay(5 * 60 * 1000L)
                DnsCacheManager.clearExpired()
            }
        }
    }
}
