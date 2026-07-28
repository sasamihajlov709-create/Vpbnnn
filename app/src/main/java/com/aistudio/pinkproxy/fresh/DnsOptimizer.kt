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
        "https://dns.controld.com/comss",
        "https://doh.pub/dns-query",
        "https://dns.alidns.com/dns-query",
        "https://doh.360.cn/dns-query",
        "https://dns0.eu/dns-query",
        "https://doh.libredns.gr/dns-query",
        "https://dns.nextdns.io/dns-query",
        "https://dns.tenta.com/dns-query",
        "https://doh.ffmuc.net/dns-query"
    )
    
    private val dotServers = listOf(
        "8.8.8.8", "1.1.1.1", "9.9.9.9", "149.112.112.112",
        "76.76.2.0", "94.140.14.14", "185.228.168.9", "76.223.122.150"
    )

    private val providerLatencies = ConcurrentHashMap<String, Long>()
    private val providerFailures = ConcurrentHashMap<String, Int>()
    @Volatile var bestDohUrl = "https://dns.google/dns-query"
    @Volatile var bestDotServer = "8.8.8.8"
    
    private var lastProbeTime = 0L
    
    private val criticalDomains = listOf(
        "google.com", "dns.google", "cloudflare.com", "telegram.org", "github.com",
        "youtube.com", "googlevideo.com", "netflix.com", "openai.com", "chatgpt.com",
        "bing.com", "duckduckgo.com", "whatsapp.com", "discord.com", "signal.org"
    )

    fun getLatencyForUrl(url: String): Long = providerLatencies[url] ?: 500L

    fun getDohUrls(): List<String> {
        // Return sorted by performance with some randomness to avoid sticking to one provider
        val rnd = java.util.concurrent.ThreadLocalRandom.current()
        return dohUrls.sortedBy { 
            val base = (providerLatencies[it] ?: 500L) + (providerFailures[it] ?: 0) * 150L
            base + rnd.nextLong(0, 50)
        }
    }
    
    fun recordDohSuccess(url: String) {
        providerFailures[url] = ((providerFailures[url] ?: 1) - 1).coerceAtLeast(0)
    }
    
    fun recordDohFailure(url: String) {
        providerFailures[url] = (providerFailures[url] ?: 0) + 1
        if (url == bestDohUrl && (providerFailures[url] ?: 0) > 3) {
            forceRefresh()
        }
    }

    fun forceRefresh() {
        if (System.currentTimeMillis() - lastProbeTime < 30000) return
        val scope = CoroutineScope(ProxyDispatcher.io + SupervisorJob())
        scope.launch {
             probeNow(null)
        }
    }

    private suspend fun probeNow(vpnService: VpnService?) {
        lastProbeTime = System.currentTimeMillis()
        coroutineScope {
            val dohJobs = dohUrls.map { url ->
                async {
                    val start = System.currentTimeMillis()
                    val res = try { withTimeout(4000) { DnsProtocols.queryDoh("google.com", url, vpnService) } } catch (e: Throwable) { emptyList() }
                    if (res.isNotEmpty()) {
                        providerLatencies[url] = System.currentTimeMillis() - start
                        providerFailures[url] = 0
                    } else {
                        providerLatencies[url] = 9999L
                        providerFailures[url] = (providerFailures[url] ?: 0) + 1
                    }
                }
            }
            val dotJobs = dotServers.map { server ->
                async {
                    val start = System.currentTimeMillis()
                    val res = try { withTimeout(4000) { DnsProtocols.queryDot("google.com", server, vpnService) } } catch (e: Throwable) { emptyList() }
                    if (res.isNotEmpty()) {
                        providerLatencies[server] = System.currentTimeMillis() - start
                        providerFailures[server] = 0
                    } else {
                        providerLatencies[server] = 9999L
                        providerFailures[server] = (providerFailures[server] ?: 0) + 1
                    }
                }
            }
            dohJobs.awaitAll()
            dotJobs.awaitAll()
            
            bestDohUrl = providerLatencies.filterKeys { it.startsWith("https") }.minByOrNull { it.value }?.key ?: dohUrls[0]
            bestDotServer = providerLatencies.filterKeys { !it.startsWith("https") }.minByOrNull { it.value }?.key ?: dotServers[0]
            Log.i("DnsOptimizer", "Probing completed. Best DoH: $bestDohUrl, Best DoT: $bestDotServer")
        }
    }

    fun start(scope: CoroutineScope, vpnService: VpnService?) {
        // Immediate Warm-up phase
        scope.launch(ProxyDispatcher.io) {
            Log.i("DnsOptimizer", "Starting DNS Warm-up...")
            probeNow(vpnService)
            criticalDomains.map { domain ->
                async {
                    try {
                        val ips = RobustResolver.resolve(domain, vpnService)
                        if (ips.isNotEmpty()) DnsCacheManager.put(domain, ips)
                    } catch (e: Throwable) {}
                }
            }.awaitAll()
            Log.i("DnsOptimizer", "DNS Warm-up completed.")
        }

        // Periodic Prober
        scope.launch(ProxyDispatcher.io) {
            while (isActive) {
                val interval = if (ProxyStats.dnsFailureCount.value > 10) 10 * 60 * 1000L else 30 * 60 * 1000L
                delay(interval)
                probeNow(vpnService)
            }
        }

        // Prefetcher
        scope.launch(ProxyDispatcher.io) {
            while (isActive) {
                delay(15 * 60 * 1000L)
                criticalDomains.map { domain ->
                    async {
                        try {
                            RobustResolver.resolve(domain, vpnService)
                        } catch (e: Throwable) {}
                    }
                }.awaitAll()
            }
        }

        // Self-Healing
        scope.launch(ProxyDispatcher.io) {
            while (isActive) {
                delay(5 * 60 * 1000L)
                DnsCacheManager.clearExpired()
            }
        }
    }
}
