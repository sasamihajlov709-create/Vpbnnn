package com.aistudio.pinkproxy.fresh

import android.net.VpnService
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
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.Dispatchers

object RobustResolver {
    private val defaultDnsServers = listOf("8.8.8.8", "1.1.1.1", "9.9.9.9", "77.88.8.8")
    private val CACHE_TTL_MS = 10 * 60 * 1000L // 10 minutes DNS cache TTL
    private val dnsCache = ConcurrentHashMap<String, Pair<List<InetAddress>, Long>>()

    @Volatile var dnsMode = "Smart DoH" // "Smart DoH" or "Custom"
    @Volatile var customDnsIp = "1.1.1.1"

    private val dohEndpoints = listOf(
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", 
        "208.67.222.222", "94.140.14.14", "45.11.45.11", "223.5.5.5", "185.222.222.222", "116.202.176.26",
        "77.88.8.8", "77.88.8.1", "dns.adguard.com", "dns.quad9.net", "doh.cleanbrowsing.org"
    )

    private val providerFailures = ConcurrentHashMap<String, Long>()

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

    fun clearCache() {
        dnsCache.clear()
        Log.d("RobustResolver", "DNS Cache cleared")
    }

    private fun getDoHEndpointsForHost(host: String): List<String> {
        val endpoints = mutableListOf<String>()
        val lHost = host.lowercase(java.util.Locale.ROOT)
        
        val now = System.currentTimeMillis()
        val healthyProviders = dohEndpoints.filter { 
            val lastFailure = providerFailures[it] ?: 0L
            now - lastFailure > 300000 // 5 minutes cool-down
        }
        val pool = if (healthyProviders.size >= 3) healthyProviders else dohEndpoints

        if (lHost.contains("google") || lHost.contains("youtube") || lHost.contains("gstatic")) {
            endpoints.addAll(listOf("8.8.8.8", "8.8.4.4", "1.1.1.1").filter { pool.contains(it) })
            if (endpoints.size < 2) endpoints.addAll(pool.shuffled().take(2))
        } else if (lHost.contains("facebook") || lHost.contains("instagram") || lHost.contains("whatsapp")) {
            endpoints.addAll(listOf("1.1.1.1", "9.9.9.9", "8.8.8.8").filter { pool.contains(it) })
            if (endpoints.size < 2) endpoints.addAll(pool.shuffled().take(2))
        } else if (lHost.contains("telegram") || lHost.contains("t.me")) {
            endpoints.addAll(listOf("149.154.167.91", "1.1.1.1", "8.8.8.8").filter { pool.contains(it) })
            if (endpoints.size < 2) endpoints.addAll(pool.shuffled().take(2))
        } else {
            endpoints.addAll(pool.shuffled().take(3))
        }
        return endpoints.distinct()
    }

    private val emergencyFallback = mapOf(
        "youtube.com" to listOf("142.250.180.142", "142.251.46.206", "2a00:1450:4001:828::200e"),
        "googlevideo.com" to listOf("172.217.16.14", "172.217.16.110"),
        "google.com" to listOf("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888"),
        "telegram.org" to listOf("149.154.167.99", "149.154.167.51"),
        "t.me" to listOf("149.154.167.99")
    )

    fun resolve(host: String, vpnService: VpnService? = null, forceSecure: Boolean = false): List<InetAddress> {
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
                    return addresses
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
                val resolved = runBlocking {
                    val results = java.util.Collections.synchronizedList(mutableListOf<InetAddress>())
                    val deferreds = endpoints.flatMap { dns ->
                        listOf(
                            async(Dispatchers.IO) {
                                withTimeoutOrNull(3000) {
                                    val r = queryDoh(host, dns, "A", vpnService)
                                    if (r.isNotEmpty()) synchronized(results) { results.addAll(r) }
                                    r
                                }
                            },
                            async(Dispatchers.IO) {
                                withTimeoutOrNull(3000) {
                                    val r = queryDoh(host, dns, "AAAA", vpnService)
                                    if (r.isNotEmpty()) synchronized(results) { results.addAll(r) }
                                    r
                                }
                            }
                        )
                    }
                    
                    // Wait for the first success or timeout
                    var attempts = 0
                    while (attempts < 15 && results.isEmpty()) {
                        kotlinx.coroutines.delay(100)
                        attempts++
                    }
                    
                    if (results.isNotEmpty()) {
                        // Let other queries run for a bit more to get AAAA if A arrived first
                        kotlinx.coroutines.delay(100)
                        results.distinct().toList()
                    } else {
                        null
                    }
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

        throw java.net.UnknownHostException("Resolution failed for $host")
    }

    private fun isIpAddress(host: String): Boolean {
        return host.matches(Regex("""^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$""")) || host.contains(":")
    }

    private val poisonedIps = setOf(
        "127.0.0.1", "0.0.0.0", "10.10.10.10", "192.168.1.1", "1.2.3.4",
        "203.0.113.1", "198.51.100.1", "185.199.108.153", "146.112.61.106",
        "10.10.34.34", "10.10.34.35", "93.184.216.34"
    )

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
        var conn: java.net.HttpURLConnection? = null
        try {
            val typeNum = if (type == "AAAA") 28 else 1
            val urlStr = if (dnsIp == "1.1.1.1" || dnsIp == "1.0.0.1") {
                "https://$dnsIp/dns-query?name=$host&type=$type"
            } else if (dnsIp == "223.5.5.5") {
                "https://$dnsIp/resolve?name=$host&type=$typeNum"
            } else {
                "https://$dnsIp/resolve?name=$host&type=$typeNum"
            }
            val url = java.net.URL(urlStr)
            conn = url.openConnection(java.net.Proxy.NO_PROXY) as java.net.HttpURLConnection
            conn.connectTimeout = 4000
            conn.readTimeout = 4000
            conn.requestMethod = "GET"
            conn.setRequestProperty("User-Agent", "Mozilla/5.0")
            
            if (dnsIp == "1.1.1.1" || dnsIp == "1.0.0.1") {
                conn.setRequestProperty("Accept", "application/dns-json")
            }
            
            if (conn.responseCode != 200) {
                providerFailures[dnsIp] = System.currentTimeMillis()
                return emptyList()
            }
            
            if (conn.responseCode == 200) {
                val responseText = conn.inputStream.bufferedReader().use { it.readText() }
                
                // Try different JSON formats (Google/Cloudflare/AdGuard)
                val ips = mutableListOf<String>()
                
                // 1. IPv4 "data" field
                val ipv4Regex = """"data"\s*:\s*"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"""".toRegex()
                // 2. IPv6 "data" field
                val ipv6Regex = """"data"\s*:\s*"([0-9a-fA-F:]+)"""".toRegex()
                
                val targetRegex = if (type == "AAAA") ipv6Regex else ipv4Regex
                ips.addAll(targetRegex.findAll(responseText).map { it.groupValues[1] })
                
                // 3. "Answer" array with "data" property
                if (ips.isEmpty()) {
                    val answerRegex = """"Answer"\s*:\s*\[.*?]""".toRegex(RegexOption.DOT_MATCHES_ALL)
                    val answerBlock = answerRegex.find(responseText)?.value
                    if (answerBlock != null) {
                        ips.addAll(targetRegex.findAll(answerBlock).map { it.groupValues[1] })
                    }
                }

                return ips.distinct()
                    .mapNotNull { try { InetAddress.getByName(it) } catch(e: Exception) { null } }
                    .filter { !isPoisoned(it, host) }
                    .toList()
            }
        } catch (e: Exception) {
            // Log.v("RobustResolver", "DoH failed: ${e.message}")
        } finally {
            try { conn?.disconnect() } catch (e: Exception) {}
        }
        return emptyList()
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

    private fun buildDnsQuery(host: String): ByteArray {
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
        dos.writeShort(1)
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
}
