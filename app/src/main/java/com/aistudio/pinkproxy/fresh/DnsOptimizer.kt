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
        "https://doh.ffmuc.net/dns-query",
        "https://doh.dns.sb/dns-query",
        "https://dns.google.com/dns-query",
        "https://common-buy.dns.google/dns-query",
        "https://unfiltered.adguard-dns.com/dns-query",
        "https://freedns.zone/dns-query"
    )
    
    private val dotServers = listOf(
        "8.8.8.8", "1.1.1.1", "9.9.9.9", "149.112.112.112",
        "76.76.2.0", "94.140.14.14", "185.228.168.9", "76.223.122.150",
        "45.90.28.0", "8.8.4.4", "1.0.0.1", "185.222.222.222"
    )

    private val doqServers = listOf(
        "94.140.14.14", "94.140.15.15", "45.90.28.0", "176.103.130.130", "1.1.1.1"
    )

    private val providerLatencies = ConcurrentHashMap<String, Long>()
    private val providerFailures = ConcurrentHashMap<String, Int>()
    @Volatile var bestDohUrl = "https://dns.google/dns-query"
    @Volatile var bestDotServer = "8.8.8.8"
    @Volatile var bestDoqServer = "94.140.14.14"
    
    private var lastProbeTime = 0L
    private val optimizerScope = CoroutineScope(ProxyDispatcher.io + SupervisorJob() + ProxyDispatcher.globalHandler)
    
    private val criticalDomains = listOf(
        "google.com", "dns.google", "cloudflare.com", "telegram.org", "github.com",
        "youtube.com", "googlevideo.com", "netflix.com", "openai.com", "chatgpt.com",
        "bing.com", "duckduckgo.com", "whatsapp.com", "discord.com", "signal.org"
    )

    /**
     * Verifies if an IP address is genuinely responding for the given domain.
     * Prevents using spoofed/poisoned DNS results.
     */
    suspend fun verifyIp(domain: String, ip: java.net.InetAddress, vpnService: android.net.VpnService?): Boolean {
        // 1. Basic Filter: Check for local/bogons and suspicious ranges
        if (ip.isLoopbackAddress || ip.isAnyLocalAddress || ip.isLinkLocalAddress || ip.isSiteLocalAddress) return false
        val host = ip.hostAddress ?: return false
        
        // Bogon and Private Ranges
        if (host.startsWith("127.") || host.startsWith("10.") || host.startsWith("192.168.") || 
            host.startsWith("172.16.") || host.startsWith("0.") || host == "255.255.255.255") return false
            
        // Check for common censorship redirect targets (from DnsPacketEngine)
        if (DnsPacketEngine.isSuspicious(ip, domain)) return false

        // 2. Connectivity Test: Try to connect to port 443 (HTTPS)
        // If it's a real IP for a global domain, it should usually respond.
        // If it's a poisoned IP, it either won't respond or will reset.
        return withContext(ProxyDispatcher.io) {
            val socket = java.net.Socket()
            try {
                try { vpnService?.protect(socket) } catch(e: Throwable) { Log.v("DnsOptimizer", "Socket protection failed: ${e.message}") }
                socket.tcpNoDelay = true
                // We use a very short timeout for verification to avoid blocking the resolver
                socket.connect(java.net.InetSocketAddress(ip, 443), 1200)
                true
            } catch (e: java.net.SocketTimeoutException) {
                // If it's a timeout, it could be DPI blocking.
                // We accept it ONLY IF it's not a known suspicious range and not a bogon.
                // For critical domains (AI, Finance), we are stricter.
                val cat = HostClassifier.classify(domain)
                cat != HostCategory.AI && cat != HostCategory.FINANCE && cat != HostCategory.SECURITY
            } catch (e: Throwable) {
                // Connection refused or reset is a strong signal of poisoning or blocking
                Log.d("DnsOptimizer", "IP verification failed for $domain ($ip): ${e.message}")
                false
            } finally {
                try { socket.close() } catch (e: Throwable) { Log.v("DnsOptimizer", "Socket close failed: ${e.message}") }
            }
        }
    }

    fun getLatencyForUrl(url: String): Long = providerLatencies[url] ?: 500L

    fun getDohUrls(): List<String> {
        // Return sorted by performance with some randomness to avoid sticking to one provider
        val rnd = java.util.concurrent.ThreadLocalRandom.current()
        val valid = dohUrls.filterNot { isUrlBlacklisted(it) }
        val pool = if (valid.isNotEmpty()) valid else dohUrls
        return pool.sortedBy { 
            val base = (providerLatencies[it] ?: 500L) + (providerFailures[it] ?: 0) * 150L
            base + rnd.nextLong(0, 50)
        }
    }
    
    private val providerBlacklist = ConcurrentHashMap<String, Long>()

    fun isUrlBlacklisted(url: String): Boolean {
        val expiry = providerBlacklist[url] ?: return false
        if (System.currentTimeMillis() > expiry) {
            providerBlacklist.remove(url)
            return false
        }
        return true
    }

    fun recordDohSuccess(url: String) {
        providerFailures[url] = ((providerFailures[url] ?: 1) - 1).coerceAtLeast(0)
    }
    
    fun recordDohFailure(url: String) {
        val f = (providerFailures[url] ?: 0) + 1
        providerFailures[url] = f
        if (f > 5) {
            // Ban for 10 minutes
            providerBlacklist[url] = System.currentTimeMillis() + 600000L
        }
        if (url == bestDohUrl && f > 3) {
            forceRefresh()
        }
    }

    fun forceRefresh() {
        if (System.currentTimeMillis() - lastProbeTime < 30000) return
        optimizerScope.launch {
             probeNow(null)
        }
    }

    private suspend fun probeNow(vpnService: VpnService?) {
        lastProbeTime = System.currentTimeMillis()
        val testDomains = listOf("google.com", "bing.com", "cloudflare.com")
        coroutineScope {
            val dohJobs = dohUrls.mapIndexed { index, url ->
                async {
                    if (index > 0) delay(index * 30L) // 30ms stagger
                    val start = System.currentTimeMillis()
                    val domain = testDomains.random()
                    val res = try { withTimeout(4000) { DnsProtocols.queryDoh(domain, url, vpnService) } } catch (e: Throwable) { 
                        if (e !is TimeoutCancellationException && e is CancellationException) throw e
                        emptyList() 
                    }
                    if (res.isNotEmpty()) {
                        providerLatencies[url] = System.currentTimeMillis() - start
                        providerFailures[url] = 0
                    } else {
                        providerLatencies[url] = 9999L
                        providerFailures[url] = (providerFailures[url] ?: 0) + 1
                    }
                }
            }
            val dotJobs = dotServers.mapIndexed { index, server ->
                async {
                    if (index > 0) delay(index * 30L) // 30ms stagger
                    val start = System.currentTimeMillis()
                    val domain = testDomains.random()
                    val res = try { withTimeout(4000) { DnsProtocols.queryDot(domain, server, vpnService) } } catch (e: Throwable) { 
                        if (e !is TimeoutCancellationException && e is CancellationException) throw e
                        emptyList() 
                    }
                    if (res.isNotEmpty()) {
                        providerLatencies[server] = System.currentTimeMillis() - start
                        providerFailures[server] = 0
                    } else {
                        providerLatencies[server] = 9999L
                        providerFailures[server] = (providerFailures[server] ?: 0) + 1
                    }
                }
            }
            val doqJobs = doqServers.mapIndexed { index, server ->
                async {
                    if (index > 0) delay(index * 30L)
                    val start = System.currentTimeMillis()
                    val domain = testDomains.random()
                    val res = try { withTimeout(4000) { DnsProtocols.queryDnsOverQuic(domain, server, vpnService) } } catch (e: Throwable) {
                        if (e !is TimeoutCancellationException && e is CancellationException) throw e
                        emptyList()
                    }
                    if (res.isNotEmpty()) {
                        providerLatencies["doq://$server"] = System.currentTimeMillis() - start
                        providerFailures["doq://$server"] = 0
                    } else {
                        providerLatencies["doq://$server"] = 9999L
                        providerFailures["doq://$server"] = (providerFailures["doq://$server"] ?: 0) + 1
                    }
                }
            }
            dohJobs.awaitAll()
            dotJobs.awaitAll()
            doqJobs.awaitAll()
            
            bestDohUrl = providerLatencies.filterKeys { it.startsWith("https") }.minByOrNull { it.value + (providerFailures[it.key] ?: 0) * 100L }?.key ?: dohUrls[0]
            bestDotServer = providerLatencies.filterKeys { !it.startsWith("https") && !it.startsWith("doq://") }.minByOrNull { it.value + (providerFailures[it.key] ?: 0) * 100L }?.key ?: dotServers[0]
            bestDoqServer = providerLatencies.filterKeys { it.startsWith("doq://") }.minByOrNull { it.value + (providerFailures[it.key] ?: 0) * 100L }?.key?.substringAfter("doq://") ?: doqServers[0]
            
            Log.i("DnsOptimizer", "Probing completed. Best DoH: $bestDohUrl, Best DoT: $bestDotServer, Best DoQ: $bestDoqServer")
        }
    }

    private var warmupJob: Job? = null
    private var proberJob: Job? = null
    private var prefetchJob: Job? = null
    private var selfHealingJob: Job? = null

    fun stop() {
        warmupJob?.cancel()
        warmupJob = null
        proberJob?.cancel()
        proberJob = null
        prefetchJob?.cancel()
        prefetchJob = null
        selfHealingJob?.cancel()
        selfHealingJob = null
    }

    fun start(scope: CoroutineScope, vpnService: VpnService?) {
        stop()

        // Immediate Warm-up phase
        warmupJob = scope.launch(ProxyDispatcher.io) {
            Log.i("DnsOptimizer", "Starting DNS Warm-up...")
            probeNow(vpnService)
            criticalDomains.map { domain ->
                async {
                    try {
                        val ips = RobustResolver.resolve(domain, vpnService)
                        if (ips.isNotEmpty()) DnsCacheManager.put(domain, ips)
                    } catch (e: Throwable) {
                        Log.v("DnsOptimizer", "Warm-up failed for $domain: ${e.message}")
                    }
                }
            }.awaitAll()
            Log.i("DnsOptimizer", "DNS Warm-up completed.")
        }

        // Periodic Prober
        proberJob = scope.launch(ProxyDispatcher.io) {
            while (isActive) {
                val interval = if (ProxyStats.dnsFailureCount.value > 10) 2 * 60 * 1000L else 15 * 60 * 1000L
                delay(interval)
                probeNow(vpnService)
            }
        }

        // Prefetcher
        prefetchJob = scope.launch(ProxyDispatcher.io) {
            while (isActive) {
                delay(15 * 60 * 1000L)
                criticalDomains.map { domain ->
                    async {
                        try {
                            RobustResolver.resolve(domain, vpnService)
                        } catch (e: Throwable) {
                            Log.v("DnsOptimizer", "Prefetch failed for $domain: ${e.message}")
                        }
                    }
                }.awaitAll()
            }
        }

        // Self-Healing
        selfHealingJob = scope.launch(ProxyDispatcher.io) {
            while (isActive) {
                delay(5 * 60 * 1000L)
                DnsCacheManager.clearExpired()
            }
        }
    }
}
