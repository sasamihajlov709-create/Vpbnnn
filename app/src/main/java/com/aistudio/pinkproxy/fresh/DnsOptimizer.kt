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
        "https://doh.opendns.com/dns-query"
    )

    private val providerLatencies = ConcurrentHashMap<String, Long>()
    @Volatile var bestDohUrl = "https://dns.google/dns-query"
    
    fun getDohUrls() = dohUrls

    private val criticalDomains = listOf(
        "youtube.com", "googlevideo.com", "google.com", "t.me", "telegram.org",
        "instagram.com", "twitter.com", "x.com", "discord.com", "chatgpt.com"
    )

    fun start(scope: CoroutineScope, vpnService: VpnService?) {
        // Immediate Warm-up phase
        scope.launch(Dispatchers.IO) {
            Log.i("DnsOptimizer", "Starting DNS Warm-up...")
            for (domain in criticalDomains) {
                try {
                    val ips = RobustResolver.resolve(domain, vpnService)
                    if (ips.isNotEmpty()) DnsCacheManager.put(domain, ips)
                } catch (e: Exception) {}
            }
            Log.i("DnsOptimizer", "DNS Warm-up completed.")
        }

        // Latency Prober
        scope.launch(Dispatchers.IO) {
            while (isActive) {
                for (url in dohUrls) {
                    val start = System.currentTimeMillis()
                    val res = DnsProtocols.queryDoh("google.com", url, vpnService)
                    if (res.isNotEmpty()) {
                        providerLatencies[url] = System.currentTimeMillis() - start
                    } else {
                        providerLatencies[url] = 9999L
                    }
                }
                bestDohUrl = providerLatencies.entries.minByOrNull { it.value }?.key ?: dohUrls[0]
                delay(10 * 60 * 1000L) // Every 10 min
            }
        }

        // Prefetcher
        scope.launch(Dispatchers.IO) {
            while (isActive) {
                for (domain in criticalDomains) {
                    try {
                        val ips = RobustResolver.resolve(domain, vpnService)
                        if (ips.isNotEmpty()) {
                            DnsCacheManager.put(domain, ips)
                        }
                    } catch (e: Exception) {}
                    delay(5000)
                }
                delay(15 * 60 * 1000L)
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
