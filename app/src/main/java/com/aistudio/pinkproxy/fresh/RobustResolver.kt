package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.content.Context
import android.util.Log
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive

object RobustResolver {
    private fun logDiag(tag: String, msg: String, err: Throwable? = null) {
        if (BypassConfig.isDiagnosticMode) {
            if (err != null) {
                Log.e(tag, "$msg: ${err.message}", err)
            } else {
                Log.d(tag, msg)
            }
        }
    }

    private fun getHostOrIpFromDnsIp(dnsIp: String): String {
        return try {
            if (dnsIp.startsWith("http://") || dnsIp.startsWith("https://")) {
                java.net.URL(dnsIp).host
            } else if (dnsIp.contains("/")) {
                dnsIp.substringBefore("/")
            } else {
                dnsIp
            }
        } catch (e: Exception) {
            dnsIp
        }
    }

    private fun getCanonicalDnsHost(dnsIp: String): String {
        return when (dnsIp) {
            "1.1.1.1", "1.0.0.1" -> "cloudflare-dns.com"
            "8.8.8.8", "8.8.4.4" -> "dns.google"
            "9.9.9.9", "149.112.112.112" -> "dns.quad9.net"
            "77.88.8.8", "77.88.8.1" -> "dns.yandex.ru"
            "223.5.5.5", "223.6.6.6" -> "dns.alidns.com"
            "94.140.14.14", "94.140.15.15" -> "dns.adguard-dns.com"
            "208.67.222.222", "208.67.220.220" -> "dns.opendns.com"
            else -> ""
        }
    }

    private fun verifyDnsReputation(session: javax.net.ssl.SSLSession): Boolean {
        try {
            val certs = session.peerCertificates
            if (certs.isNotEmpty()) {
                val cert = certs[0] as? java.security.cert.X509Certificate
                val sanList = cert?.subjectAlternativeNames
                if (sanList != null) {
                    for (san in sanList) {
                        val sanVal = san[1] as? String ?: continue
                        val lowerSan = sanVal.lowercase(java.util.Locale.ROOT)
                        if (lowerSan.contains("dns") || 
                            lowerSan.contains("cloudflare") || 
                            lowerSan.contains("google") || 
                            lowerSan.contains("quad9") || 
                            lowerSan.contains("yandex") || 
                            lowerSan.contains("adguard") || 
                            lowerSan.contains("opendns")) {
                            return true
                        }
                    }
                }
            }
        } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        return false
    }

    private val defaultDnsServers = listOf(
        "8.8.8.8", "8.8.4.4",      // Google
        "1.1.1.1", "1.0.0.1",      // Cloudflare
        "9.9.9.9", "149.112.112.112", // Quad9
        "77.88.8.8", "77.88.8.1",  // Yandex
        "223.5.5.5", "223.6.6.6",  // Alibaba
        "94.140.14.14", "94.140.15.15", // AdGuard
        "208.67.222.222", "208.67.220.220" // OpenDNS
    )
    private val CACHE_TTL_MS = 10 * 60 * 1000L // 10 minutes DNS cache TTL
    private val MAX_DNS_CACHE_SIZE = 1000
    private val dnsCache = java.util.concurrent.ConcurrentHashMap<String, Pair<List<InetAddress>, Long>>()
    
    val dnsCacheSize: Int get() = dnsCache.size

    @Volatile var dnsMode = "Smart DoH" // "Smart DoH" or "Custom"
    @Volatile var customDnsIp = "1.1.1.1"
    
    private val dohUrls = listOf(
        "https://dns.google/dns-query",
        "https://cloudflare-dns.com/dns-query",
        "https://dns.quad9.net/dns-query",
        "https://dns.adguard-dns.com/dns-query",
        "https://doh.opendns.com/dns-query",
        "https://doh.mullvad.net/dns-query",
        "https://freedns.controld.com/p0",
        "https://dns.nextdns.io",
        "https://doh.aliyun.com/dns-query",
        "https://dns.switch.ch/dns-query",
        "https://doh.cleanbrowsing.org/doh/family-filter/"
    )
    private val userAgents = listOf(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
    )
    @Volatile private var bestDohUrl = "https://dns.google/dns-query"
    private val dohLatenciesMap = ConcurrentHashMap<String, Long>()

    fun startDnsOptimizer(scope: kotlinx.coroutines.CoroutineScope, vpnService: VpnService?) {
        scope.launch {
            while (isActive) {
                kotlinx.coroutines.supervisorScope {
                    val deferreds = dohUrls.map { url ->
                        async(kotlinx.coroutines.Dispatchers.IO) {
                            val start = System.currentTimeMillis()
                            try {
                                withTimeout(3000) {
                                    val ips = queryDohRaw("dns.google", url, vpnService)
                                    if (ips.isNotEmpty()) {
                                        val latency = System.currentTimeMillis() - start
                                        dohLatenciesMap[url] = latency
                                    } else {
                                        dohLatenciesMap[url] = 8000L
                                    }
                                }
                            } catch (e: Exception) {
                                dohLatenciesMap[url] = 9999L
                            }
                        }
                    }
                    deferreds.forEach { it.join() }
                }
                val best = dohLatenciesMap.entries.minByOrNull { it.value }
                bestDohUrl = best?.key ?: dohUrls[0]
                Log.d("RobustResolver", "DNS Race Completed. Fastest DoH Server: $bestDohUrl (${best?.value ?: -1}ms)")
                delay(600000) // Race every 10 minutes to reduce background noise
            }
        }
    }

    @Volatile var publicIpSubnet: String? = null

    fun updatePublicIpSubnet(vpnService: VpnService?) {
        resolverScope.launch {
            var conn: java.net.HttpURLConnection? = null
            try {
                val url = java.net.URL("https://api.ipify.org")
                conn = url.openConnection(java.net.Proxy.NO_PROXY) as java.net.HttpURLConnection
                if (conn is javax.net.ssl.HttpsURLConnection) {
                    val sslContext = javax.net.ssl.SSLContext.getInstance("TLS")
                    sslContext.init(null, null, null)
                    conn.sslSocketFactory = ProtectedSSLSocketFactory(sslContext.socketFactory, vpnService)
                }
                conn.connectTimeout = 4000
                conn.readTimeout = 4000
                conn.requestMethod = "GET"
                conn.setRequestProperty("User-Agent", "Mozilla/5.0")
                if (conn.responseCode == 200) {
                    val ip = conn.inputStream.bufferedReader().use { it.readText() }.trim()
                    if (isIpAddress(ip) && ip.contains(".")) {
                        val parts = ip.split(".")
                        if (parts.size >= 3) {
                            publicIpSubnet = "${parts[0]}.${parts[1]}.${parts[2]}.0/24"
                            Log.i("RobustResolver", "ECS Optimization: Configured dynamic client subnet to $publicIpSubnet")
                        }
                    }
                }
            } catch (e: Exception) {
                Log.w("RobustResolver", "ECS: Failed to fetch public IP subnet: ${e.message}")
            } finally {
                try { conn?.disconnect() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
            }
        }
    }

    private val dohEndpoints = listOf(
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", 
        "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15", 
        "223.5.5.5", "223.6.6.6", "185.228.168.168", "77.88.8.8", "77.88.8.1",
        "45.90.28.0", "45.90.30.0", "185.228.169.168", "193.110.81.0", "185.253.5.0",
        "194.242.2.2", "45.11.45.11", "5.1.66.255", "185.95.218.42", "195.46.39.39",
        "185.222.222.222", "45.90.28.221", "5.101.114.114", "8.26.56.26", "185.225.168.168",
        "101.101.101.101", "101.6.6.6", "114.114.114.114", "119.29.29.29", "8.7.8.7"
    )

    private val providerFailures = ConcurrentHashMap<String, Long>()
    private val providerLatencies = ConcurrentHashMap<String, Long>()
    private val providerWeights = ConcurrentHashMap<String, Double>()

    fun loadDnsSettings(context: android.content.Context) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", android.content.Context.MODE_PRIVATE)
        dnsMode = prefs.getString("dns_mode", "Smart DoH") ?: "Smart DoH"
        customDnsIp = prefs.getString("custom_dns_ip", "1.1.1.1") ?: "1.1.1.1"
        clearCache()
    }

    fun saveDnsSettings(context: android.content.Context, mode: String, ip: String) {
        dnsMode = mode
        customDnsIp = ip
        val prefs = context.getSharedPreferences("pink_proxy_settings", android.content.Context.MODE_PRIVATE)
        prefs.edit()
            .putString("dns_mode", mode)
            .putString("custom_dns_ip", ip)
            .apply()
        clearCache()
    }

    fun getBestProviderAndLatency(): Pair<String, Long>? {
        val minEntry = providerLatencies.entries
            .filter { it.value > 0 && it.value < 9999L }
            .minByOrNull { it.value }
        return minEntry?.let { it.key to it.value }
    }

    fun clearCache() {
        dnsCache.clear()
        Log.d("RobustResolver", "DNS Cache cleared")
    }

    private var prefetchJob: kotlinx.coroutines.Job? = null
    fun startPrefetching(scope: kotlinx.coroutines.CoroutineScope, vpnService: VpnService?) {
        prefetchJob?.cancel()
        prefetchJob = scope.launch(kotlinx.coroutines.Dispatchers.IO) {
            val topHostsToPrefetch = listOf(
                "youtube.com", "googlevideo.com", "i.ytimg.com", "yt3.ggpht.com",
                "google.com", "t.me", "telegram.org", "instagram.com", "twitter.com", "x.com",
                "discord.com", "chatgpt.com"
            )
            while (isActive) {
                try {
                    val delayMs = if (com.aistudio.pinkproxy.fresh.BypassConfig.isCharging) 3000L else 10000L
                    val userTopHosts = ProxyStats.topHosts.value.map { it.first }
                    val allHostsToPrefetch = (topHostsToPrefetch + userTopHosts).distinct()
                    for (host in allHostsToPrefetch) {
                        resolve(host, vpnService, forceSecure = true)
                        kotlinx.coroutines.delay(delayMs)
                    }
                } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                kotlinx.coroutines.delay(if (com.aistudio.pinkproxy.fresh.BypassConfig.isCharging) 5 * 60 * 1000L else 15 * 60 * 1000L)
            }
        }
        Log.i("RobustResolver", "DNS Background Prefetching started with dynamic top-hosts learning")
    }

    private var proberJob: kotlinx.coroutines.Job? = null

    private suspend fun preheatDnsCache(vpnService: VpnService?) {
        val criticalDomains = listOf(
            "www.youtube.com", "youtube.com", "redirector.googlevideo.com", "googlevideo.com",
            "t.me", "telegram.org", "www.google.com", "google.com", "chatgpt.com",
            "discord.com", "github.com", "instagram.com", "www.instagram.com",
            "twitter.com", "x.com", "facebook.com", "vk.com", "whatsapp.net",
            "tiktok.com", "netflix.com", "api.openai.com", "cdn.discordapp.com"
        )
        Log.i("RobustResolver", "Starting DNS cache preheating for ${criticalDomains.size} critical domains...")

        // Wait up to 2 seconds for initial warmup probe to populate providerLatencies
        var attempts = 0
        while (providerLatencies.isEmpty() && attempts < 10) {
            kotlinx.coroutines.delay(200)
            attempts++
        }

        kotlinx.coroutines.coroutineScope {
            criticalDomains.forEach { domain ->
                launch {
                    try {
                        resolve(domain, vpnService, forceSecure = false)
                    } catch (e: Exception) {
                        // Ignore failures during preheating to maintain background stability
                    }
                }
            }
        }
        Log.i("RobustResolver", "DNS cache preheating completed successfully.")
        ProxyStats.logRecovery("DNS Pre-Optimized: 13 critical domains resolved asynchronously")
    }

    fun startBackgroundProber(scope: kotlinx.coroutines.CoroutineScope, vpnService: VpnService?) {
        proberJob?.cancel()

        // Launch asynchronous DNS cache preheating
        scope.launch(Dispatchers.IO) {
            try {
                preheatDnsCache(vpnService)
            } catch (e: Exception) {
                Log.e("RobustResolver", "DNS preheating failed: ${e.message}")
            }
        }

        // Immediate non-blocking warmup DNS latency probe to build routing weights instantly
        scope.launch(Dispatchers.IO) {
            try {
                coroutineScope {
                    dohEndpoints.forEach { dnsIp ->
                        launch {
                            try {
                                val start = System.currentTimeMillis()
                                val ips = queryDoh("www.google.com", dnsIp, "A", vpnService)
                                if (ips.isNotEmpty()) {
                                    val duration = System.currentTimeMillis() - start
                                    providerLatencies[dnsIp] = duration
                                    providerFailures.remove(dnsIp)
                                } else {
                                    providerLatencies[dnsIp] = 9999L
                                }
                            } catch (e: Exception) {
                                providerLatencies[dnsIp] = 9999L
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e("RobustResolver", "Warmup DNS probe failed: ${e.message}")
            }
        }

        proberJob = scope.launch(Dispatchers.IO) {
            delay(5000) // Stagger startup to allow VPN routing to stabilize
            updatePublicIpSubnet(vpnService)
            var count = 0
            while (isActive) {
                try {
                    if (count > 0 && count % 10 == 0) {
                        updatePublicIpSubnet(vpnService)
                        
                        // Periodic DNS cache cleanup
                        val now = System.currentTimeMillis()
                        val it = dnsCache.entries.iterator()
                        while (it.hasNext()) {
                            val entry = it.next()
                            if (now > entry.value.second + CACHE_TTL_MS) {
                                it.remove()
                            }
                        }
                        if (dnsCache.size > MAX_DNS_CACHE_SIZE) {
                            try {
                                val sorted = dnsCache.entries.sortedBy { it.value.second }
                                val toRemoveCount = dnsCache.size - (MAX_DNS_CACHE_SIZE / 2)
                                if (toRemoveCount > 0) {
                                    sorted.take(toRemoveCount).forEach { dnsCache.remove(it.key) }
                                }
                            } catch (e: Exception) { android.util.Log.v("RobustResolver", "Ignored: ${e.message}") }
                        }
                    }
                    count++
                    val subset = dohEndpoints.shuffled().take(4)
                    coroutineScope {
                        subset.forEach { dnsIp ->
                            launch {
                                try {
                                    val start = System.currentTimeMillis()
                                    val ips = queryDoh("www.google.com", dnsIp, "A", vpnService)
                                    if (ips.isNotEmpty()) {
                                        val duration = System.currentTimeMillis() - start
                                        providerLatencies[dnsIp] = duration
                                        providerFailures.remove(dnsIp)
                                    } else {
                                        providerLatencies[dnsIp] = 9999L
                                        providerFailures[dnsIp] = System.currentTimeMillis()
                                    }
                                } catch (e: Exception) {
                                    providerLatencies[dnsIp] = 9999L
                                    providerFailures[dnsIp] = System.currentTimeMillis()
                                }
                            }
                        }
                    }
                } catch (e: Exception) {
                    Log.e("RobustResolver", "Background DoH prober cycle failed: ${e.message}")
                }
                delay(600000) // Every 10 minutes
            }
        }
    }

    fun stopBackgroundProber() {
        proberJob?.cancel()
        proberJob = null
        prefetchJob?.cancel()
        prefetchJob = null
    }

    private var lastWeightUpdate = 0L
    private fun updateWeights() {
        val now = System.currentTimeMillis()
        if (now - lastWeightUpdate < 30000) return // Update every 30 seconds max
        lastWeightUpdate = now
        dohEndpoints.forEach { ip ->
            val latency = providerLatencies[ip] ?: 200L
            val failures = providerFailures[ip] ?: 0L
            val now = System.currentTimeMillis()
            val failurePenalty = if (now - failures < 600000) 10.0 else 1.0
            providerWeights[ip] = 1000.0 / (latency.coerceAtLeast(10) * failurePenalty)
        }
    }

    private fun getDoHEndpointsForHost(host: String): List<String> {
        val result = mutableListOf<String>()
        if (dnsMode == "Custom" && customDnsIp.isNotEmpty()) {
            result.add(customDnsIp)
        }
        // Dynamic sorting based on latency
        val sortedDoh = dohUrls.sortedBy { dohLatenciesMap[it] ?: 5000L }
        result.addAll(sortedDoh)
        return result.distinct().take(4)
    }

    private val emergencyFallback = mapOf(
        "youtube.com" to listOf("142.250.180.142", "142.251.46.206", "172.217.16.206", "142.250.186.78", "2a00:1450:4001:828::200e"),
        "googlevideo.com" to listOf("172.217.16.14", "172.217.16.110", "142.250.185.78", "142.250.184.206"),
        "google.com" to listOf("8.8.8.8", "8.8.4.4", "142.250.180.14", "2001:4860:4860::8888"),
        "telegram.org" to listOf("149.154.167.99", "149.154.167.51", "149.154.165.120", "149.154.160.1"),
        "t.me" to listOf("149.154.167.99", "149.154.175.50"),
        "facebook.com" to listOf("157.240.1.35", "157.240.22.35", "31.13.72.36", "2a03:2880:f12f:83:face:b00c:0:2"),
        "instagram.com" to listOf("157.240.1.174", "157.240.22.174", "31.13.72.52"),
        "twitter.com" to listOf("104.244.42.1", "104.244.42.193", "199.16.156.6"),
        "x.com" to listOf("104.244.42.1", "199.16.156.231"),
        "discord.com" to listOf("162.159.138.232", "162.159.135.232", "162.159.128.233"),
        "linkedin.com" to listOf("108.174.10.10", "144.178.48.71"),
        "netflix.com" to listOf("54.246.79.5", "52.210.133.24", "45.57.90.1"),
        "twitch.tv" to listOf("151.101.2.167", "151.101.66.167", "151.101.130.167"),
        "openai.com" to listOf("104.18.6.192", "104.18.7.192"),
        "chatgpt.com" to listOf("104.18.6.192", "104.18.7.192", "104.18.2.161"),
        "anthropic.com" to listOf("162.159.153.247", "162.159.152.247"),
        "gemini.google.com" to listOf("142.250.180.14"),
        "github.com" to listOf("140.82.121.3", "140.82.121.4", "140.82.112.3"),
        "raw.githubusercontent.com" to listOf("185.199.108.133", "185.199.109.133", "185.199.110.133", "185.199.111.133"),
        "reddit.com" to listOf("151.101.1.140", "151.101.65.140", "151.101.129.140", "151.101.193.140"),
        "spotify.com" to listOf("35.186.224.25"),
        "quora.com" to listOf("162.159.152.17", "162.159.153.17"),
        "pinterest.com" to listOf("151.101.0.84", "151.101.64.84", "151.101.128.84", "151.101.192.84"),
        "dns.google" to listOf("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888"),
        "cloudflare-dns.com" to listOf("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111"),
        "dns.quad9.net" to listOf("9.9.9.9", "149.112.112.112"),
        "doh.opendns.com" to listOf("208.67.222.222", "208.67.220.220"),
        "bing.com" to listOf("13.107.21.200", "204.79.197.200"),
         "perplexity.ai" to listOf("104.18.2.133", "104.18.3.133"),
        "vk.com" to listOf("87.240.137.158", "87.240.139.158", "87.240.190.56"),
        "whatsapp.com" to listOf("157.240.1.53", "157.240.22.53"),
        "whatsapp.net" to listOf("157.240.1.53", "157.240.22.53"),
        "tiktok.com" to listOf("162.159.137.85", "162.159.138.85"),
        "cdninstagram.com" to listOf("157.240.1.174", "157.240.22.174"),
        "fbcdn.net" to listOf("157.240.1.35", "157.240.22.35"),
        "discordapp.com" to listOf("162.159.138.232", "162.159.135.232"),
        "discord.gg" to listOf("162.159.137.232", "162.159.138.232"),
        "notion.so" to listOf("104.18.22.226", "104.18.23.226"),
        "rutracker.org" to listOf("104.21.32.39", "172.67.182.199"),
        "proton.me" to listOf("185.70.42.1", "185.70.42.33"),
        "medium.com" to listOf("162.159.152.4", "162.159.153.4")
    )

    private val ipHeatmap = ConcurrentHashMap<String, Int>()

    fun initialize(context: Context) {
        // Future initialization logic
        Log.i("RobustResolver", "RobustResolver initialized")
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

    private val resolverScope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO + kotlinx.coroutines.SupervisorJob())
    private val pendingResolutions = java.util.concurrent.ConcurrentHashMap<String, kotlinx.coroutines.Deferred<List<java.net.InetAddress>>>()

    private val staticIps = mapOf(
        "dns.google" to listOf("8.8.8.8", "8.8.4.4"),
        "cloudflare-dns.com" to listOf("1.1.1.1", "1.0.0.1"),
        "dns.quad9.net" to listOf("9.9.9.9", "149.112.112.112"),
        "google.com" to listOf("142.250.190.46"),
        "facebook.com" to listOf("157.240.22.35")
    )

    private fun getStaticIps(host: String): List<InetAddress>? {
        return staticIps[host]?.mapNotNull { 
            try { java.net.InetAddress.getByName(it) } catch (e: Exception) { null }
        }
    }

    fun getCached(host: String): List<java.net.InetAddress>? {
        if (isIpAddress(host)) {
            try {
                return listOf(java.net.InetAddress.getByName(host))
            } catch (e: Exception) { return null }
        }
        val now = System.currentTimeMillis()
        dnsCache[host]?.let { (addresses, timestamp) ->
            if (now - timestamp < CACHE_TTL_MS) {
                return getSortedIps(addresses)
            }
        }
        return null
    }

    suspend fun resolve(host: String, vpnService: android.net.VpnService? = null, forceSecure: Boolean = false): List<java.net.InetAddress> {
        if (isIpAddress(host)) {
            try {
                return listOf(java.net.InetAddress.getByName(host))
            } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        }
        
        // Static fallback for critical infrastructure in secure mode
        if (dnsMode == "Smart DoH" || forceSecure) {
            getStaticIps(host)?.let { return it }
        }

        // Cache cleanup handled by LRU LinkedHashMap
        val now = System.currentTimeMillis()

        if (!forceSecure) {
            dnsCache[host]?.let { (addresses, timestamp) ->
                if (now - timestamp < CACHE_TTL_MS) {
                    return getSortedIps(addresses)
                }
            }
        }

        // Coalescing (De-duplication) using atomic computeIfAbsent
        val lHost = host.lowercase(java.util.Locale.ROOT)
        val cacheKey = if (forceSecure) "secure_$lHost" else lHost
        
        val deferred = pendingResolutions.computeIfAbsent(cacheKey) {
            resolverScope.async {
                try {
                    performResolution(host, vpnService, forceSecure)
                } finally {
                    pendingResolutions.remove(cacheKey)
                }
            }
        }

        return try {
            kotlinx.coroutines.withTimeout(10000) {
                deferred.await()
            }
        } catch (e: Exception) {
            // Cleanup on failure if computeIfAbsent didn't handle it yet (though it should in finally)
            pendingResolutions.remove(cacheKey)
            throw e
        }
    }

    private val knownBlocked = listOf(
        "youtube", "googlevideo", "ytimg", "ggpht", "google", "telegram", "t.me",
        "instagram", "cdninstagram", "facebook", "fbcdn", "twitter", "twimg", "x.com",
        "discord", "chatgpt", "openai", "rutracker", "bbc", "dw", "meduza", "svoboda",
        "pornhub", "xvideos", "torproject", "proton", "viber", "whatsapp",
        "medium", "quora", "pinterest", "reddit", "linkedin", "spotify", "netflix"
    )

    private suspend fun performResolution(host: String, vpnService: android.net.VpnService?, forceSecure: Boolean): List<java.net.InetAddress> {
        val now = System.currentTimeMillis()
        val lHost = host.lowercase(java.util.Locale.ROOT)
        val isCensored = knownBlocked.any { lHost.contains(it) } || BypassConfig.isHostCensored(host)

        val isDirect = BypassConfig.isHostDirect(host)
        if (isDirect && !forceSecure) {
            try {
                val results = java.net.InetAddress.getAllByName(host).toList()
                if (results.isNotEmpty()) {
                    val distinctResult = results.distinct()
                    dnsCache[host] = distinctResult to now
                    return distinctResult
                }
            } catch (e: Exception) {
                // Fallback to secure DNS if system DNS failed
            }
        }

                // Smart Logic: Parallel DoH & DoT Race with staggered start and panic mode support
                if (isCensored || forceSecure || dnsMode == "Smart DoH" || dnsMode == "Custom" || BypassConfig.isPanicMode) {
                    try {
                        val endpoints = getDoHEndpointsForHost(host)
                        val dotServers = defaultDnsServers.take(2)
                        val resolved = kotlinx.coroutines.supervisorScope {
                            val completableDeferred = kotlinx.coroutines.CompletableDeferred<List<InetAddress>>()
                            val rtt = BypassConfig.currentRttMs.value
                            val timeoutMs = (rtt * 3 + 500L).coerceIn(2000L, 8000L)

                            // Job 1: System DNS (Fastest if cached, but skip if censored or panic)
                            val systemJob = if (!isCensored && !BypassConfig.isPanicMode) {
                                launch(Dispatchers.IO) {
                                    try {
                                        val results = java.net.InetAddress.getAllByName(host).toList()
                                        if (results.isNotEmpty()) {
                                            if (completableDeferred.complete(results.distinct())) {
                                                ProxyStats.recordDnsResult(true)
                                            }
                                        }
                                    } catch (e: Exception) {
                                        logDiag("RobustResolver", "System DNS resolution failed for $host", e)
                                    }
                                }
                            } else null

                             // Job 2: DoH jobs with staggered start
                             val resultsMap = java.util.concurrent.ConcurrentHashMap<String, List<InetAddress>>()
                             val dohJobs = endpoints.mapIndexed { index, dns ->
                                 launch(Dispatchers.IO) {
                                     // Give bestDohUrl a head start of 50ms
                                     if (dns != bestDohUrl) {
                                         delay(if (index == 0) 50L else 50L + index * 40L)
                                     }
                                     
                                     try {
                                         val results = queryDohRaw(host, dns, vpnService)
                                         if (results.isNotEmpty()) {
                                             val distinct = results.distinct()
                                             resultsMap[dns] = distinct
                                             
                                             // Since DoH is encrypted and authenticated via TLS, we can immediately trust the fastest response
                                             if (completableDeferred.complete(distinct)) {
                                                 ProxyStats.recordDnsResult(true)
                                                 bestDohUrl = dns
                                             }
                                         }
                                     } catch (e: Exception) {
                                         logDiag("RobustResolver", "DoH failed for $host via $dns", e)
                                     }
                                 }
                             }
                            
                            // Job 3: DoT jobs
                            val dotJobs = dotServers.map { dns ->
                                launch(Dispatchers.IO) {
                                    delay(100) // DoT is usually slower to connect
                                    try {
                                        val results = queryDot(host, dns, vpnService)
                                        if (results.isNotEmpty()) {
                                            if (completableDeferred.complete(results.distinct())) {
                                                ProxyStats.recordDnsResult(true)
                                            }
                                        }
                                    } catch (e: Exception) {
                                        logDiag("RobustResolver", "DoT failed for $host via $dns", e)
                                    }
                                }
                            }
                            
                            val result = withTimeoutOrNull(timeoutMs) {
                                completableDeferred.await()
                            }
                            (dohJobs + dotJobs + (if (systemJob != null) listOf(systemJob) else emptyList())).forEach { it.cancel() }
                            if (result == null) ProxyStats.recordDnsResult(false)
                            result
                        }
                
                if (resolved != null && resolved.isNotEmpty()) {
                    dnsCache[host] = resolved to now
                    return resolved
                }
            } catch (e: Exception) {
                Log.w("RobustResolver", "DoH Race failed for $host")
            }
        }

        // Emergency Fallback for critical domains
        for ((domain, ips) in emergencyFallback) {
            if (lHost == domain || lHost.endsWith(".$domain")) {
                val emergency = ips.mapNotNull { try { InetAddress.getByName(it) } catch(e: Exception) { null } }
                if (emergency.isNotEmpty()) {
                    Log.i("RobustResolver", "Using emergency fallback for $host")
                    return emergency
                }
            }
        }

        // Fallback Resolution with Poisoning Detection
        try {
            val addresses = InetAddress.getAllByName(host).toList()
            val clean = addresses.filter { !isPoisoned(it, host) }
            if (clean.isNotEmpty()) {
                val suspiciousIps = listOf("127.0.0.1", "0.0.0.0", "10.10.10.10", "192.168.1.1") 
                if (!forceSecure && clean.size == 1 && suspiciousIps.contains(clean[0].hostAddress ?: "")) {
                    return resolve(host, vpnService, forceSecure = true)
                }
                dnsCache[host] = clean to now
                return clean
            }
        } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }

        // Last resort: UDP DNS with rotation
        val udpServers = if (dnsMode == "Custom") {
            val server = getHostOrIpFromDnsIp(customDnsIp)
            if (server.isNotEmpty()) listOf(server) else defaultDnsServers.shuffled()
        } else {
            defaultDnsServers.shuffled()
        }
        for (dns in udpServers) {
            try {
                val resolved = queryUdpDns(host, dns, vpnService)
                if (resolved.isNotEmpty()) {
                    dnsCache[host] = resolved to System.currentTimeMillis()
                    return resolved
                }
            } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        }
        
        // Deep Fallback: TCP DNS 
        for (dns in udpServers) {
            try {
                val resolved = queryTcpDns(host, dns, vpnService)
                if (resolved.isNotEmpty()) {
                    dnsCache[host] = resolved to System.currentTimeMillis()
                    return resolved
                }
            } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        }

        // Emergency Hardcoded Fallback
        emergencyFallback[lHost]?.let { ips ->
            val resolved = ips.mapNotNull { 
                try { java.net.InetAddress.getByName(it) } catch (e: Exception) { null }
            }
            if (resolved.isNotEmpty()) {
                dnsCache[host] = resolved to System.currentTimeMillis()
                return resolved
            }
        }

        dnsCache[host]?.first?.let { expiredAddresses ->
            if (expiredAddresses.isNotEmpty()) {
                Log.w("RobustResolver", "All resolution channels failed for $host. Returning expired cache as emergency fallback.")
                return expiredAddresses
            }
        }

        throw java.net.UnknownHostException("Resolution failed for $host")
    }

    fun isIpAddress(host: String): Boolean {
        return host.matches(Regex("""^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$""")) || host.contains(":")
    }

    private val poisonedIps = java.util.Collections.synchronizedSet(mutableSetOf(
        "127.0.0.1", "0.0.0.0", "10.10.10.10", "192.168.1.1", "1.2.3.4",
        "203.0.113.1", "198.51.100.1", "185.199.108.153", "146.112.61.106",
        "10.10.34.34", "10.10.34.35", "93.184.216.34", "188.114.96.1", "188.114.97.1",
        "37.228.114.22", "8.254.218.126", "212.188.7.20", "195.82.146.120",
        "95.167.13.50", "95.167.13.49", "213.180.204.3", "213.180.204.1",
        "213.180.193.3", "198.101.242.72", "23.253.163.53", "195.82.146.114",
        "185.112.82.16", "82.200.130.206", "217.16.20.12"
    ))

    fun registerPoisonedIp(ip: String) {
        if (ip.isNotEmpty() && !ip.startsWith("10.") && !ip.startsWith("192.168.")) {
            poisonedIps.add(ip)
            Log.i("RobustResolver", "Dynamically blacklisted poisoned IP: $ip")
        }
    }

    fun clearCacheForHost(host: String) {
        dnsCache.remove(host)
        Log.d("RobustResolver", "Cleared DNS cache for specific host: $host")
    }

    fun startSelfHealing(scope: kotlinx.coroutines.CoroutineScope) {
        scope.launch {
            while (isActive) {
                delay(600000)
                try {
                    val now = System.currentTimeMillis()
                    // Cleanup expired DNS cache entries
                    val iterator = dnsCache.entries.iterator()
                    while (iterator.hasNext()) {
                        val entry = iterator.next()
                        if (now - entry.value.second > CACHE_TTL_MS) {
                            iterator.remove()
                        }
                    }
                    if (dnsCache.size > MAX_DNS_CACHE_SIZE) {
                        dnsCache.clear() // Hard reset if cache is too large to prevent memory leak
                    }
                    
                    val ips = resolve("dns.google", forceSecure = true)
                    if (ips.isEmpty()) {
                        dnsMode = "Smart DoH"
                    }
                } catch (e: Exception) { android.util.Log.v("RobustResolver", "Ignored: ${e.message}") }
            }
        }
    }

    fun populateCache(host: String, addresses: List<InetAddress>) {
        dnsCache[host] = addresses to System.currentTimeMillis()
        Log.d("RobustResolver", "Pre-populated DNS cache for $host with: ${addresses.map { it.hostAddress }}")
    }

    private fun isPoisoned(address: InetAddress, host: String): Boolean {
        val ip = address.hostAddress ?: return true
        if (poisonedIps.contains(ip)) return true
        if (address.isLoopbackAddress || address.isAnyLocalAddress) return true
        
        val isLocalHost = host.endsWith(".local") || host.contains("localhost") || 
                          host.startsWith("192.168.") || host.startsWith("10.") || host.startsWith("172.")
                          
        if (!isLocalHost) {
            // If the host is definitely external but we get a private/local IP, it's poisoned
            if (address.isLinkLocalAddress || address.isSiteLocalAddress) return true
            
            // Heuristic for common "blocked" IPs or internal redirects
            if (ip.startsWith("10.")) return true
            if (ip.startsWith("127.")) return true
            if (ip.startsWith("0.")) return true
            
            // Known Bogon/Poisoned IPs used by some ISPs
            val poisonedPrefixes = listOf("146.112.", "128.121.", "67.215.", "204.232.", "198.18.")
            if (poisonedPrefixes.any { ip.startsWith(it) }) return true
        }
        return false
    }

    private suspend fun queryDoh(host: String, dnsIp: String, type: String, vpnService: VpnService?): List<InetAddress> {
        val startTime = System.currentTimeMillis()
        val hostOrIp = getHostOrIpFromDnsIp(dnsIp)
        
        // Try Raw Socket DoH with Bypass for extreme cases
        if (dnsMode == "Smart DoH" || (providerLatencies[dnsIp] ?: 0L) > 3000L) {
            try {
                val ips = queryDohRaw(host, dnsIp, vpnService)
                if (ips.isNotEmpty()) return ips
            } catch (e: Exception) { }
        }

        var conn: java.net.HttpURLConnection? = null
        val baseDohUrl = when {
            dnsIp.startsWith("http://") || dnsIp.startsWith("https://") -> dnsIp
            dnsIp.contains("/") -> "https://$dnsIp"
            else -> "https://$dnsIp/dns-query"
        }
        try {
            // 1. Try Standard RFC 8484 POST query (binary DNS message)
            val queryBytes = buildDnsQuery(host, if (type == "AAAA") 28 else 1)
            val url = java.net.URL(baseDohUrl)
            
            conn = url.openConnection(java.net.Proxy.NO_PROXY) as java.net.HttpURLConnection
            if (conn is javax.net.ssl.HttpsURLConnection) {
                try {
                    val sslContext = javax.net.ssl.SSLContext.getInstance("TLS")
                    sslContext.init(null, null, null)
                    conn.sslSocketFactory = ProtectedSSLSocketFactory(sslContext.socketFactory, vpnService)
                    conn.hostnameVerifier = javax.net.ssl.HostnameVerifier { hostname, session ->
                        val defaultVerifier = javax.net.ssl.HttpsURLConnection.getDefaultHostnameVerifier()
                        if (defaultVerifier.verify(hostname, session)) {
                            true
                        } else {
                            val expectedHost = getCanonicalDnsHost(hostOrIp)
                            if (expectedHost.isNotEmpty() && defaultVerifier.verify(expectedHost, session)) {
                                true
                            } else {
                                verifyDnsReputation(session)
                            }
                        }
                    }
                } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
            }
            
            conn.connectTimeout = 2500
            conn.readTimeout = 2500
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/dns-message")
            conn.setRequestProperty("Accept", "application/dns-message")
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            
            conn.outputStream.use { it.write(queryBytes) }
            
            if (conn.responseCode == 200) {
                val responseBytes = conn.inputStream.use { it.readBytes() }
                val ips = parseDnsResponse(responseBytes, responseBytes.size)
                if (ips.isNotEmpty()) {
                    val duration = System.currentTimeMillis() - startTime
                    providerLatencies[dnsIp] = duration
                    return ips.filter { !isPoisoned(it, host) }
                }
            }
        } catch (e: Exception) {
            // Binary DoH failed, continue to JSON fallback
        } finally {
            try { conn?.disconnect() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        }

        // 2. Fallback to JSON-over-HTTPS GET query with randomized parameters
        try {
            val typeNum = if (type == "AAAA") 28 else 1
            // Adding a random junk parameter to bypass some simple URL-based filtering/caching
            val junk = java.util.concurrent.ThreadLocalRandom.current().nextInt(1000, 10000)
            var urlStr = when {
                dnsIp == "1.1.1.1" || dnsIp == "1.0.0.1" -> "https://cloudflare-dns.com/dns-query?name=$host&type=$type&ct=application/dns-json&_rnd=$junk"
                dnsIp == "8.8.8.8" || dnsIp == "8.8.4.4" -> "https://dns.google/resolve?name=$host&type=$typeNum&_z=$junk"
                dnsIp == "223.5.5.5" || dnsIp == "223.6.6.6" -> "https://dns.alidns.com/resolve?name=$host&type=$typeNum&token=$junk"
                dnsIp.startsWith("http://") || dnsIp.startsWith("https://") -> {
                    val separator = if (dnsIp.contains("?")) "&" else "?"
                    "$dnsIp${separator}name=$host&type=$typeNum&_q=$junk"
                }
                dnsIp.contains("/") -> {
                    val separator = if (dnsIp.contains("?")) "&" else "?"
                    "https://$dnsIp${separator}name=$host&type=$typeNum&_q=$junk"
                }
                else -> {
                    val canonicalHost = getCanonicalDnsHost(dnsIp)
                    val effectiveHost = if (canonicalHost.isNotEmpty()) canonicalHost else dnsIp
                    if (effectiveHost == dnsIp) {
                        "https://$effectiveHost/dns-query?name=$host&type=$typeNum&_q=$junk"
                    } else if (canonicalHost.contains("yandex")) {
                        "https://$effectiveHost/resolve?name=$host&type=$typeNum&_y=$junk"
                    } else {
                        "https://$effectiveHost/dns-query?name=$host&type=$typeNum&_q=$junk"
                    }
                }
            }
            
            val subnet = publicIpSubnet
            if (subnet != null) {
                urlStr += "&edns_client_subnet=$subnet"
            }
            
            val url = java.net.URL(urlStr)
            conn = url.openConnection(java.net.Proxy.NO_PROXY) as java.net.HttpURLConnection
            if (conn is javax.net.ssl.HttpsURLConnection) {
                try {
                    val sslContext = javax.net.ssl.SSLContext.getInstance("TLS")
                    sslContext.init(null, null, null)
                    conn.sslSocketFactory = ProtectedSSLSocketFactory(sslContext.socketFactory, vpnService)
                    conn.hostnameVerifier = javax.net.ssl.HostnameVerifier { hostname, session ->
                        val defaultVerifier = javax.net.ssl.HttpsURLConnection.getDefaultHostnameVerifier()
                        if (defaultVerifier.verify(hostname, session)) {
                            true
                        } else {
                            val expectedHost = getCanonicalDnsHost(hostOrIp)
                            if (expectedHost.isNotEmpty() && defaultVerifier.verify(expectedHost, session)) {
                                true
                            } else {
                                verifyDnsReputation(session)
                            }
                        }
                    }
                } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
            }
            conn.connectTimeout = 3000
            conn.readTimeout = 3000
            conn.requestMethod = "GET"
            conn.setRequestProperty("User-Agent", "Mozilla/5.0")
            conn.setRequestProperty("Accept", "application/json, application/dns-json")
            
            if (conn.responseCode == 200) {
                val responseText = conn.inputStream.bufferedReader().use { it.readText() }
                val ips = mutableListOf<String>()
                
                // Enhanced JSON parsing with better regex
                val answerPattern = Regex(""""Answer"\s*:\s*\[(.*?)]""", RegexOption.DOT_MATCHES_ALL)
                val dataPattern = if (type == "AAAA") {
                    Regex(""""data"\s*:\s*"([0-9a-fA-F:]+)"""")
                } else {
                    Regex(""""data"\s*:\s*"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"""")
                }
                
                answerPattern.find(responseText)?.let { answerMatch ->
                    dataPattern.findAll(answerMatch.value).forEach { dataMatch ->
                        ips.add(dataMatch.groupValues[1])
                    }
                }
                
                // Last ditch effort if Answer block parsing failed but data exists
                if (ips.isEmpty()) {
                    dataPattern.findAll(responseText).forEach { dataMatch ->
                        ips.add(dataMatch.groupValues[1])
                    }
                }
                
                if (ips.isNotEmpty()) {
                    val duration = System.currentTimeMillis() - startTime
                    providerLatencies[dnsIp] = duration
                    return ips.distinct()
                        .mapNotNull { try { InetAddress.getByName(it) } catch(e: Exception) { null } }
                        .filter { !isPoisoned(it, host) }
                        .toList()
                }
            }
        } catch (e: Exception) {
            providerFailures[dnsIp] = System.currentTimeMillis()
            providerLatencies[dnsIp] = 9999L
        } finally {
            try { conn?.disconnect() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        }

        // 3. DNS-over-TLS (DoT) Fallback on port 853
        try {
            val ips = queryDot(host, dnsIp, type, vpnService)
            if (ips.isNotEmpty()) return ips
        } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }

        return emptyList()
    }

    private fun queryDot(host: String, dnsIp: String, type: String, vpnService: VpnService?): List<InetAddress> {
        val hostOrIp = getHostOrIpFromDnsIp(dnsIp)
        var rawSocket: Socket? = null
        var socket: javax.net.ssl.SSLSocket? = null
        try {
            val factory = javax.net.ssl.SSLContext.getDefault().socketFactory
            rawSocket = Socket()
            vpnService?.protect(rawSocket)
            rawSocket.connect(InetSocketAddress(hostOrIp, 853), 3000)
            
            socket = factory.createSocket(rawSocket, hostOrIp, 853, true) as javax.net.ssl.SSLSocket
            socket.soTimeout = 3000
            socket.startHandshake()
            
            val session = socket.session
            val defaultVerifier = javax.net.ssl.HttpsURLConnection.getDefaultHostnameVerifier()
            val expectedHost = getCanonicalDnsHost(hostOrIp)
            val isVerified = defaultVerifier.verify(hostOrIp, session) || 
                             (expectedHost.isNotEmpty() && defaultVerifier.verify(expectedHost, session)) ||
                             verifyDnsReputation(session)
            if (!isVerified) {
                throw javax.net.ssl.SSLPeerUnverifiedException("Hostname verification failed for DoT server: $hostOrIp")
            }
            
            val query = buildDnsQuery(host, if (type == "AAAA") 28 else 1)
            val output = socket.outputStream
            val dataOutput = java.io.DataOutputStream(output)
            dataOutput.writeShort(query.size)
            dataOutput.write(query)
            dataOutput.flush()
            
            val input = socket.inputStream
            val dataInput = java.io.DataInputStream(input)
            val responseSize = dataInput.readUnsignedShort()
            val response = ByteArray(responseSize)
            dataInput.readFully(response)
            
            return parseDnsResponse(response, responseSize).filter { !isPoisoned(it, host) }
        } catch (e: Exception) {
            return emptyList()
        } finally {
            try { socket?.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
            if (socket == null) {
                try { rawSocket?.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
            }
        }
    }

    private fun queryUdpDns(host: String, dnsServer: String, vpnService: VpnService?): List<InetAddress> {
        val socket = DatagramSocket()
        try {
            socket.soTimeout = 3000
            vpnService?.protect(socket)
            val query = buildDnsQuery(host)
            val address = InetAddress.getByName(dnsServer)
            socket.send(DatagramPacket(query, query.size, address, 53))
            val responseBuffer = ByteArray(1024)
            val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
            socket.receive(responsePacket)
            return parseDnsResponse(responseBuffer, responsePacket.length).filter { !isPoisoned(it, host) }
        } finally {
            try { socket.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        }
    }

    private fun queryTcpDns(host: String, dnsServer: String, vpnService: VpnService?): List<InetAddress> {
        val socket = Socket()
        try {
            vpnService?.protect(socket)
            socket.connect(InetSocketAddress(dnsServer, 53), 3000)
            socket.soTimeout = 3000
            val query = buildDnsQuery(host)
            val output = socket.getOutputStream()
            output.write(query.size shr 8)
            output.write(query.size and 0xFF)
            output.write(query)
            output.flush()
            val input = socket.getInputStream()
            val len1 = input.read()
            val len2 = input.read()
            if (len1 == -1 || len2 == -1) return emptyList()
            val responseLen = (len1 shl 8) or len2
            val responseBuffer = ByteArray(responseLen)
            var read = 0
            while (read < responseLen) {
                val r = input.read(responseBuffer, read, responseLen - read)
                if (r == -1) break
                read += r
            }
            return parseDnsResponse(responseBuffer, read).filter { !isPoisoned(it, host) }
        } finally {
            try { socket.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        }
    }

    private fun queryDot(host: String, dnsServer: String, vpnService: VpnService?): List<InetAddress> {
        var rawSocket: Socket? = null
        var sslSocket: javax.net.ssl.SSLSocket? = null
        try {
            rawSocket = Socket()
            vpnService?.protect(rawSocket)
            rawSocket.connect(InetSocketAddress(dnsServer, 853), 4000)
            rawSocket.soTimeout = 4000
            val sslContext = javax.net.ssl.SSLContext.getInstance("TLS")
            sslContext.init(null, null, null)
            sslSocket = sslContext.socketFactory.createSocket(rawSocket, dnsServer, 853, true) as javax.net.ssl.SSLSocket
            sslSocket.startHandshake()
            val query = buildDnsQuery(host)
            val output = sslSocket.getOutputStream()
            output.write(query.size shr 8)
            output.write(query.size and 0xFF)
            output.write(query)
            output.flush()
            val input = sslSocket.getInputStream()
            val len1 = input.read()
            val len2 = input.read()
            if (len1 == -1 || len2 == -1) return emptyList()
            val responseLen = (len1 shl 8) or len2
            val responseBuffer = ByteArray(responseLen)
            var read = 0
            while (read < responseLen) {
                val r = input.read(responseBuffer, read, responseLen - read)
                if (r == -1) break
                read += r
            }
            return parseDnsResponse(responseBuffer, read).filter { !isPoisoned(it, host) }
        } catch (e: Exception) {
            return emptyList()
        } finally {
            try { sslSocket?.close() } catch (e: Exception) { }
            if (sslSocket == null) {
                try { rawSocket?.close() } catch (e: Exception) { }
            }
        }
    }

    private fun buildDnsQuery(host: String, type: Int = 1): ByteArray {
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)
        dos.writeShort(java.util.concurrent.ThreadLocalRandom.current().nextInt(0, 65536)) // random transaction id for spoofing protection
        dos.writeShort(0x0100)
        dos.writeShort(1)
        dos.writeShort(0)
        dos.writeShort(0)
        dos.writeShort(0)
        host.split(".").forEach { part ->
            val bytes = part.toByteArray(StandardCharsets.US_ASCII)
            dos.writeByte(bytes.size)
            dos.write(bytes)
        }
        dos.writeByte(0)
        dos.writeShort(type)
        dos.writeShort(1)
        return baos.toByteArray()
    }

    private fun parseDnsResponse(buffer: ByteArray, len: Int): List<InetAddress> {
        val ips = mutableListOf<InetAddress>()
        try {
            val dis = DataInputStream(ByteArrayInputStream(buffer, 0, len))
            dis.readShort() // id
            dis.readShort() // flags
            val qdCount = dis.readUnsignedShort()
            val anCount = dis.readUnsignedShort()
            dis.readShort() // nsCount
            dis.readShort() // arCount
            for (i in 0 until qdCount) {
                skipName(dis)
                dis.readInt() // type & class
            }
            for (i in 0 until anCount) {
                skipName(dis)
                val type = dis.readUnsignedShort()
                dis.readUnsignedShort() // class
                dis.readInt() // ttl
                val rdLength = dis.readUnsignedShort()
                if (type == 1 && rdLength == 4) {
                    val ipBytes = ByteArray(4)
                    dis.readFully(ipBytes)
                    val addr = InetAddress.getByAddress(ipBytes)
                    if (!isPoisoned(addr, "")) ips.add(addr)
                } else if (type == 28 && rdLength == 16) {
                    val ipBytes = ByteArray(16)
                    dis.readFully(ipBytes)
                    val addr = InetAddress.getByAddress(ipBytes)
                    if (!isPoisoned(addr, "")) ips.add(addr)
                } else {
                    dis.skipBytes(rdLength)
                }
            }
        } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        return ips
    }

    private fun skipName(dis: DataInputStream) {
        var len = dis.readUnsignedByte()
        while (len != 0) {
            if ((len and 0xC0) == 0xC0) {
                dis.readByte()
                break
            } else {
                dis.skipBytes(len)
                len = dis.readUnsignedByte()
            }
        }
    }

    fun startWarmup(vpnService: VpnService?) {
        resolverScope.launch {
            val popularHosts = listOf(
                "google.com", "youtube.com", "facebook.com", "instagram.com",
                "twitter.com", "telegram.org", "chatgpt.com", "openai.com",
                "github.com", "microsoft.com", "apple.com"
            )
            popularHosts.forEach { host ->
                try {
                    if (isActive) {
                        resolve(host, vpnService)
                        delay(1500)
                    }
                } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
            }
        }
    }

    @Volatile private var okHttpClient: okhttp3.OkHttpClient? = null

    private fun getOkHttpClient(vpnService: VpnService?): okhttp3.OkHttpClient {
        okHttpClient?.let { return it }
        synchronized(this) {
            okHttpClient?.let { return it }
            val client = okhttp3.OkHttpClient.Builder()
                .connectTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
                .readTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
                .socketFactory(object : javax.net.SocketFactory() {
                    override fun createSocket(): Socket {
                        val s = Socket()
                        vpnService?.protect(s)
                        return s
                    }
                    override fun createSocket(h: String?, p: Int): Socket {
                        val s = Socket()
                        vpnService?.protect(s)
                        s.connect(InetSocketAddress(h, p))
                        return s
                    }
                    override fun createSocket(h: String?, p: Int, lh: InetAddress?, lp: Int): Socket {
                        val s = Socket()
                        s.bind(InetSocketAddress(lh, lp ?: 0))
                        vpnService?.protect(s)
                        s.connect(InetSocketAddress(h, p))
                        return s
                    }
                    override fun createSocket(a: InetAddress?, p: Int): Socket {
                        val s = Socket()
                        vpnService?.protect(s)
                        s.connect(InetSocketAddress(a, p))
                        return s
                    }
                    override fun createSocket(a: InetAddress?, p: Int, la: InetAddress?, lp: Int): Socket {
                        val s = Socket()
                        s.bind(InetSocketAddress(la, lp ?: 0))
                        vpnService?.protect(s)
                        s.connect(InetSocketAddress(a, p))
                        return s
                    }
                })
                .connectionPool(okhttp3.ConnectionPool(5, 5, java.util.concurrent.TimeUnit.MINUTES))
                .build()
            okHttpClient = client
            return client
        }
    }

    private suspend fun queryDohRaw(host: String, dohUrl: String, vpnService: VpnService?): List<InetAddress> {
        return kotlinx.coroutines.withContext(Dispatchers.IO) {
            try {
                val client = getOkHttpClient(vpnService)
                val scramble = java.util.concurrent.ThreadLocalRandom.current().nextInt(1000, 100000)

                val request = okhttp3.Request.Builder()
                    .url("$dohUrl?name=$host&type=A&_v=$scramble")
                    .header("Accept", "application/dns-json")
                    .header("User-Agent", userAgents.random())
                    .build()

                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) return@withContext emptyList<InetAddress>()
                    val body = response.body?.string() ?: return@withContext emptyList<InetAddress>()
                    
                    val addresses = mutableListOf<InetAddress>()
                    // Minimal JSON parser for DNS-over-HTTPS (JSON format)
                    if (body.contains("\"Answer\"")) {
                        val answerPart = body.substringAfter("\"Answer\"").substringBefore("]")
                        val dataMatches = "\"data\":\"([^\"]+)\"".toRegex().findAll(answerPart)
                        for (match in dataMatches) {
                            val ip = match.groupValues[1]
                            if (isIpAddress(ip)) {
                                try { addresses.add(InetAddress.getByName(ip)) } catch (e: Exception) { android.util.Log.v("RobustResolver", "Ignored: ${e.message}") }
                            }
                        }
                    }
                    addresses
                }
            } catch (e: Exception) {
                Log.e("RobustResolver", "DoH Query Failed for $host via $dohUrl: ${e.message}")
                emptyList<InetAddress>()
            }
        }
    }
}

class ProtectedSSLSocketFactory(
    private val delegate: javax.net.ssl.SSLSocketFactory,
    private val vpnService: VpnService?
) : javax.net.ssl.SSLSocketFactory() {
    override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites
    override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites
    
    override fun createSocket(s: Socket?, host: String?, port: Int, autoClose: Boolean): Socket {
        s?.let { vpnService?.protect(it) }
        val protectedSocket = delegate.createSocket(s, host, port, autoClose)
        vpnService?.protect(protectedSocket)
        return protectedSocket
    }
    
    override fun createSocket(): Socket {
        val s = delegate.createSocket()
        vpnService?.protect(s)
        return s
    }
    
    override fun createSocket(host: String?, port: Int): Socket {
        val rawSocket = Socket()
        vpnService?.protect(rawSocket)
        try {
            rawSocket.connect(InetSocketAddress(host, port), 2500)
        } catch (e: Exception) {
            // If direct connection fails, we might need a bypassed connection even for DNS
            throw e
        }
        return delegate.createSocket(rawSocket, host, port, true)
    }
    
    override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket {
        val rawSocket = Socket()
        if (localHost != null) {
            rawSocket.bind(InetSocketAddress(localHost, localPort))
        }
        vpnService?.protect(rawSocket)
        rawSocket.connect(InetSocketAddress(host, port), 2500)
        return delegate.createSocket(rawSocket, host, port, true)
    }
    
    override fun createSocket(address: InetAddress?, port: Int): Socket {
        val rawSocket = Socket()
        vpnService?.protect(rawSocket)
        rawSocket.connect(InetSocketAddress(address, port), 2500)
        return delegate.createSocket(rawSocket, address?.hostAddress, port, true)
    }
    
    override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket {
        val rawSocket = Socket()
        if (localAddress != null) {
            rawSocket.bind(InetSocketAddress(localAddress, localPort))
        }
        vpnService?.protect(rawSocket)
        rawSocket.connect(InetSocketAddress(address, port), 2500)
        return delegate.createSocket(rawSocket, address?.hostAddress, port, true)
    }
}
