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
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive

object RobustResolver {
    private val defaultDnsServers = listOf("8.8.8.8", "1.1.1.1", "9.9.9.9", "77.88.8.8")
    private val CACHE_TTL_MS = 10 * 60 * 1000L // 10 minutes DNS cache TTL
    private val dnsCache = ConcurrentHashMap<String, Pair<List<InetAddress>, Long>>()

    @Volatile var dnsMode = "Smart DoH" // "Smart DoH" or "Custom"
    @Volatile var customDnsIp = "1.1.1.1"

    @Volatile var publicIpSubnet: String? = null

    fun updatePublicIpSubnet(vpnService: VpnService?) {
        kotlinx.coroutines.CoroutineScope(Dispatchers.IO).launch {
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
                try { conn?.disconnect() } catch (e: Exception) {}
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
    fun startPrefetching(vpnService: VpnService?) {
        prefetchJob?.cancel()
        prefetchJob = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
            val topHostsToPrefetch = listOf(
                "youtube.com", "googlevideo.com", "i.ytimg.com", "yt3.ggpht.com",
                "google.com", "t.me", "telegram.org", "instagram.com", "twitter.com", "x.com",
                "discord.com", "chatgpt.com"
            )
            while (isActive) {
                try {
                    val userTopHosts = ProxyStats.topHosts.value.map { it.first }
                    val allHostsToPrefetch = (topHostsToPrefetch + userTopHosts).distinct()
                    for (host in allHostsToPrefetch) {
                        resolve(host, vpnService, forceSecure = true)
                        kotlinx.coroutines.delay(2000)
                    }
                } catch (e: Exception) {}
                kotlinx.coroutines.delay(5 * 60 * 1000L)
            }
        }
        Log.i("RobustResolver", "DNS Background Prefetching started with dynamic top-hosts learning")
    }

    private var proberJob: kotlinx.coroutines.Job? = null

    private suspend fun preheatDnsCache(vpnService: VpnService?) {
        val criticalDomains = listOf(
            "www.youtube.com", "youtube.com", "redirector.googlevideo.com", "googlevideo.com",
            "t.me", "telegram.org", "www.google.com", "google.com", "chatgpt.com",
            "discord.com", "github.com", "instagram.com", "www.instagram.com"
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
                delay(120000) // Every 2 minutes
            }
        }
    }

    fun stopBackgroundProber() {
        proberJob?.cancel()
        proberJob = null
    }

    private fun updateWeights() {
        dohEndpoints.forEach { ip ->
            val latency = providerLatencies[ip] ?: 200L
            val failures = providerFailures[ip] ?: 0L
            val now = System.currentTimeMillis()
            val failurePenalty = if (now - failures < 600000) 10.0 else 1.0
            providerWeights[ip] = 1000.0 / (latency.coerceAtLeast(10) * failurePenalty)
        }
    }

    private fun getDoHEndpointsForHost(host: String): List<String> {
        updateWeights()
        val now = System.currentTimeMillis()
        val pool = dohEndpoints.filter { 
            val lastFailure = providerFailures[it] ?: 0L
            now - lastFailure > 300000 // 5 minutes cool-down
        }.sortedByDescending { providerWeights[it] ?: 0.0 }

        if (pool.isEmpty()) return dohEndpoints.shuffled().take(3)
        
        val result = mutableListOf<String>()
        val lHost = host.lowercase(java.util.Locale.ROOT)
        
        if (lHost.contains("google") || lHost.contains("youtube")) {
            result.addAll(listOf("8.8.8.8", "8.8.4.4").filter { pool.contains(it) })
        } else if (lHost.contains("cloudflare")) {
            result.addAll(listOf("1.1.1.1", "1.0.0.1").filter { pool.contains(it) })
        }
        
        result.addAll(pool.take(5))
        return result.distinct().take(3)
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
        "raw.githubusercontent.com" to listOf("185.199.108.133", "185.199.109.133", "185.199.110.133", "185.199.111.133")
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

    suspend fun resolve(host: String, vpnService: VpnService? = null, forceSecure: Boolean = false): List<InetAddress> {
        if (isIpAddress(host)) {
            try {
                return listOf(InetAddress.getByName(host))
            } catch (e: Exception) {}
        }

        // Cache lookup
        val now = System.currentTimeMillis()
        if (dnsCache.size > 2000) {
            dnsCache.entries.removeIf { now - it.value.second > CACHE_TTL_MS }
        }

        if (!forceSecure) {
            dnsCache[host]?.let { (addresses, timestamp) ->
                if (now - timestamp < CACHE_TTL_MS) {
                    return getSortedIps(addresses)
                }
            }
        }

        val lHost = host.lowercase(java.util.Locale.ROOT)
        val knownBlocked = listOf(
            "youtube", "googlevideo", "ytimg", "ggpht", "google", "telegram", "t.me",
            "instagram", "cdninstagram", "facebook", "fbcdn", "twitter", "twimg", "x.com",
            "discord", "chatgpt", "openai", "rutracker", "bbc", "dw", "meduza", "svoboda",
            "pornhub", "xvideos", "torproject", "proton", "viber", "whatsapp"
        )
        val isCensored = knownBlocked.any { lHost.contains(it) }

        // Smart Logic: Parallel DoH Race
        if (isCensored || forceSecure || dnsMode == "Smart DoH") {
            try {
                val endpoints = getDoHEndpointsForHost(host)
                val resolved = coroutineScope {
                    val completableDeferred = kotlinx.coroutines.CompletableDeferred<List<InetAddress>>()
                    val jobs = endpoints.map { dns ->
                        launch(Dispatchers.IO) {
                            try {
                                val ips = mutableListOf<InetAddress>()
                                val aJob = async { queryDoh(host, dns, "A", vpnService) }
                                val aaaaJob = async { queryDoh(host, dns, "AAAA", vpnService) }
                                
                                val aResults = aJob.await()
                                val aaaaResults = aaaaJob.await()
                                
                                ips.addAll(aResults)
                                ips.addAll(aaaaResults)
                                
                                if (ips.isNotEmpty()) {
                                    completableDeferred.complete(ips.distinct())
                                }
                            } catch (e: Exception) {
                                // ignore
                            }
                        }
                    }
                    
                    val result = withTimeoutOrNull(3000) {
                        completableDeferred.await()
                    }
                    jobs.forEach { it.cancel() }
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
                if (clean.size == 1 && suspiciousIps.contains(clean[0].hostAddress ?: "")) {
                    return resolve(host, vpnService, forceSecure = true)
                }
                dnsCache[host] = clean to now
                return clean
            }
        } catch (e: Exception) {}

        // Last resort: UDP DNS with rotation
        val udpServers = if (dnsMode == "Custom") listOf(customDnsIp) else defaultDnsServers.shuffled()
        for (dns in udpServers) {
            try {
                val resolved = queryUdpDns(host, dns, vpnService)
                if (resolved.isNotEmpty()) {
                    dnsCache[host] = resolved to System.currentTimeMillis()
                    return resolved
                }
            } catch (e: Exception) {}
        }
        
        // Deep Fallback: TCP DNS 
        for (dns in udpServers) {
            try {
                val resolved = queryTcpDns(host, dns, vpnService)
                if (resolved.isNotEmpty()) {
                    dnsCache[host] = resolved to System.currentTimeMillis()
                    return resolved
                }
            } catch (e: Exception) {}
        }

        dnsCache[host]?.first?.let { expiredAddresses ->
            if (expiredAddresses.isNotEmpty()) {
                Log.w("RobustResolver", "All resolution channels failed for $host. Returning expired cache as emergency fallback.")
                return expiredAddresses
            }
        }

        throw java.net.UnknownHostException("Resolution failed for $host")
    }

    private fun isIpAddress(host: String): Boolean {
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
        }
        return false
    }

    private fun queryDoh(host: String, dnsIp: String, type: String, vpnService: VpnService?): List<InetAddress> {
        val startTime = System.currentTimeMillis()
        var conn: java.net.HttpURLConnection? = null
        try {
            // 1. Try Standard RFC 8484 POST query (binary DNS message)
            val queryBytes = buildDnsQuery(host, if (type == "AAAA") 28 else 1)
            val url = java.net.URL("https://$dnsIp/dns-query")
            
            conn = url.openConnection(java.net.Proxy.NO_PROXY) as java.net.HttpURLConnection
            if (conn is javax.net.ssl.HttpsURLConnection) {
                try {
                    val sslContext = javax.net.ssl.SSLContext.getInstance("TLS")
                    sslContext.init(null, null, null)
                    conn.sslSocketFactory = ProtectedSSLSocketFactory(sslContext.socketFactory, vpnService)
                    conn.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
                } catch (e: Exception) {}
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
            try { conn?.disconnect() } catch (e: Exception) {}
        }

        // 2. Fallback to JSON-over-HTTPS GET query with randomized parameters
        try {
            val typeNum = if (type == "AAAA") 28 else 1
            // Adding a random junk parameter to bypass some simple URL-based filtering/caching
            val junk = (1000..9999).random()
            var urlStr = when (dnsIp) {
                "1.1.1.1", "1.0.0.1" -> "https://$dnsIp/dns-query?name=$host&type=$type&ct=application/dns-json&_rnd=$junk"
                "8.8.8.8", "8.8.4.4" -> "https://dns.google/resolve?name=$host&type=$typeNum&_z=$junk"
                "223.5.5.5", "223.6.6.6" -> "https://dns.alidns.com/resolve?name=$host&type=$typeNum&token=$junk"
                else -> "https://$dnsIp/resolve?name=$host&type=$typeNum&_q=$junk"
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
                    conn.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
                } catch (e: Exception) {}
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
            try { conn?.disconnect() } catch (e: Exception) {}
        }

        // 3. DNS-over-TLS (DoT) Fallback on port 853
        try {
            val ips = queryDot(host, dnsIp, type, vpnService)
            if (ips.isNotEmpty()) return ips
        } catch (e: Exception) {}

        return emptyList()
    }

    private fun queryDot(host: String, dnsIp: String, type: String, vpnService: VpnService?): List<InetAddress> {
        var socket: javax.net.ssl.SSLSocket? = null
        try {
            val factory = javax.net.ssl.SSLContext.getDefault().socketFactory
            val rawSocket = Socket()
            vpnService?.protect(rawSocket)
            rawSocket.connect(InetSocketAddress(dnsIp, 853), 3000)
            
            socket = factory.createSocket(rawSocket, dnsIp, 853, true) as javax.net.ssl.SSLSocket
            socket.soTimeout = 3000
            socket.startHandshake()
            
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
            try { socket?.close() } catch (e: Exception) {}
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
            return parseDnsResponse(responseBuffer, responsePacket.length)
        } finally {
            try { socket.close() } catch (e: Exception) {}
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
            return parseDnsResponse(responseBuffer, read)
        } finally {
            try { socket.close() } catch (e: Exception) {}
        }
    }

    private fun buildDnsQuery(host: String, type: Int = 1): ByteArray {
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)
        dos.writeShort(0x1234)
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
        } catch (e: Exception) {}
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
        kotlinx.coroutines.CoroutineScope(Dispatchers.IO).launch {
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
                } catch (e: Exception) {}
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
        rawSocket.connect(InetSocketAddress(host, port), 2500)
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
