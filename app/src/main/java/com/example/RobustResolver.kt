package com.example

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

object RobustResolver {
    private val dnsServers = listOf("8.8.8.8", "1.1.1.1", "9.9.9.9", "77.88.8.8")
    private val CACHE_TTL_MS = 10 * 60 * 1000L // 10 minutes DNS cache TTL
    private val dnsCache = ConcurrentHashMap<String, Pair<List<InetAddress>, Long>>()

    fun clearCache() {
        dnsCache.clear()
        Log.d("RobustResolver", "DNS Cache cleared")
    }

    fun resolve(host: String, vpnService: VpnService? = null, forceSecure: Boolean = false): List<InetAddress> {
        // If it's already an IP address, return it
        if (isIpAddress(host)) {
            try {
                return listOf(InetAddress.getByName(host))
            } catch (e: Exception) {
                // Fallback
            }
        }

        if (dnsCache.size > 1000) {
            val now = System.currentTimeMillis()
            dnsCache.entries.removeIf { now - it.value.second > CACHE_TTL_MS }
        }

        // Check cache with TTL (ignore/remove cache if forceSecure is requested)
        if (forceSecure) {
            dnsCache.remove(host)
        } else {
            dnsCache[host]?.let { (addresses, timestamp) ->
                if (System.currentTimeMillis() - timestamp < CACHE_TTL_MS) {
                    return addresses
                } else {
                    dnsCache.remove(host)
                }
            }
        }

        // Try standard resolution first for uncensored domains to avoid overhead
        val knownBlocked = listOf(
            "youtube", "googlevideo", "ytimg", "ggpht", "google", "telegram", "t.me",
            "instagram", "cdninstagram", "facebook", "fbcdn", "twitter", "twimg", "x.com",
            "discord", "chatgpt", "openai", "rutracker", "bbc", "dw", "meduza", "svoboda",
            "pornhub", "xvideos", "torproject", "proton", "viber", "whatsapp"
        )
        val isCensored = knownBlocked.any { host.lowercase(java.util.Locale.ROOT).contains(it) }

        if (!isCensored && !forceSecure) {
            try {
                val addresses = InetAddress.getAllByName(host).toList()
                // Filter out obviously poisoned addresses (like 127.0.0.1, 0.0.0.0, or private IPs if resolving public domains)
                val clean = addresses.filter { !isPoisoned(it, host) }
                if (clean.isNotEmpty()) {
                    dnsCache[host] = clean to System.currentTimeMillis()
                    return clean
                }
            } catch (e: Exception) {
                Log.w("RobustResolver", "Standard DNS failed for $host, trying secure fallback...")
            }
        } else {
            Log.d("RobustResolver", "Censored host detected: $host. Skipping standard DNS to prevent ISP hijacking.")
        }

        // Try DNS-over-HTTPS (DoH) fallback to bypass ISP port 53 blocking/hijacking
        val dohServers = listOf("1.1.1.1", "8.8.8.8", "1.0.0.1", "8.8.4.4")
        for (dns in dohServers) {
            try {
                val resolved = queryDoh(host, dns, vpnService)
                if (resolved.isNotEmpty()) {
                    dnsCache[host] = resolved to System.currentTimeMillis()
                    return resolved
                }
            } catch (e: Exception) {
                Log.w("RobustResolver", "DoH query failed to $dns for $host: ${e.message}")
            }
        }

        // Try UDP DNS queries to public DNS servers
        for (dns in dnsServers) {
            try {
                val resolved = queryUdpDns(host, dns, vpnService)
                if (resolved.isNotEmpty()) {
                    dnsCache[host] = resolved to System.currentTimeMillis()
                    return resolved
                }
            } catch (e: Exception) {
                Log.w("RobustResolver", "UDP DNS query failed to $dns for $host: ${e.message}")
            }
        }

        // Try TCP DNS queries to public DNS servers (port 53)
        for (dns in dnsServers) {
            try {
                val resolved = queryTcpDns(host, dns, vpnService)
                if (resolved.isNotEmpty()) {
                    dnsCache[host] = resolved to System.currentTimeMillis()
                    return resolved
                }
            } catch (e: Exception) {
                Log.w("RobustResolver", "TCP DNS query failed to $dns for $host: ${e.message}")
            }
        }

        throw java.net.UnknownHostException("Could not resolve $host via any mechanism")
    }

    private fun isIpAddress(host: String): Boolean {
        return host.matches(Regex("""^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$""")) || host.contains(":")
    }

    private fun isPoisoned(address: InetAddress, host: String): Boolean {
        val ip = address.hostAddress ?: return true
        if (ip == "127.0.0.1" || ip == "0.0.0.0") return true
        if (address.isLoopbackAddress || address.isAnyLocalAddress) return true
        
        // Private IP spaces (unless the host is local)
        val isLocalHost = host.endsWith(".local") || host.contains("localhost") || host.startsWith("192.168.") || host.startsWith("10.")
        if (!isLocalHost) {
            if (address.isLinkLocalAddress || address.isSiteLocalAddress) return true
        }
        return false
    }

    private fun queryDoh(host: String, dnsIp: String, vpnService: VpnService?): List<InetAddress> {
        var conn: java.net.HttpURLConnection? = null
        try {
            val urlStr = if (dnsIp == "1.1.1.1" || dnsIp == "1.0.0.1") {
                "https://$dnsIp/dns-query?name=$host&type=A"
            } else {
                "https://$dnsIp/resolve?name=$host&type=1"
            }
            val url = java.net.URL(urlStr)
            conn = url.openConnection(java.net.Proxy.NO_PROXY) as java.net.HttpURLConnection
            conn.connectTimeout = 4000
            conn.readTimeout = 4000
            conn.requestMethod = "GET"
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            
            if (dnsIp == "1.1.1.1" || dnsIp == "1.0.0.1") {
                conn.setRequestProperty("Accept", "application/dns-json")
            }
            
            val responseCode = conn.responseCode
            if (responseCode == 200) {
                val responseText = conn.inputStream.bufferedReader().use { it.readText() }
                val regex = """"data"\s*:\s*"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"""".toRegex()
                val matches = regex.findAll(responseText)
                val resolved = matches.map { it.groupValues[1] }
                    .distinct()
                    .mapNotNull {
                        try { InetAddress.getByName(it) } catch(e: Exception) { null }
                    }
                    .filter { !isPoisoned(it, host) }
                    .toList()
                return resolved
            }
        } catch (e: Exception) {
            Log.w("RobustResolver", "DoH failed for $host via $dnsIp: ${e.message}")
        } finally {
            try { conn?.inputStream?.close() } catch (e: Exception) {}
            try { conn?.errorStream?.close() } catch (e: Exception) {}
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
            val packet = DatagramPacket(query, query.size, address, 53)
            socket.send(packet)

            val responseBuffer = ByteArray(1024)
            val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
            socket.receive(responsePacket)

            return parseDnsResponse(responseBuffer, responsePacket.length)
        } finally {
            try {
                socket.close()
            } catch (e: Exception) {
                // Ignore
            }
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
            val len = query.size
            output.write(len shr 8)
            output.write(len and 0xFF)
            output.write(query)
            output.flush()

            val input = socket.getInputStream()
            val len1 = input.read()
            val len2 = input.read()
            if (len1 == -1 || len2 == -1) {
                return emptyList()
            }
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
            try {
                socket.close()
            } catch (e: Exception) {
                // Ignore
            }
        }
    }

    private fun buildDnsQuery(host: String): ByteArray {
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)

        // Transaction ID (2 bytes)
        dos.writeShort(0x1234)
        // Flags: Standard query (0x0100)
        dos.writeShort(0x0100)
        // Questions count (1)
        dos.writeShort(1)
        // Answers resource records count (0)
        dos.writeShort(0)
        // Authority resource records count (0)
        dos.writeShort(0)
        // Additional resource records count (0)
        dos.writeShort(0)

        // Name (encoded as label lengths and bytes)
        val parts = host.split(".")
        for (part in parts) {
            val bytes = part.toByteArray(StandardCharsets.US_ASCII)
            dos.writeByte(bytes.size)
            dos.write(bytes)
        }
        dos.writeByte(0) // Null byte terminates the domain name

        // Type: A record (0x0001)
        dos.writeShort(1)
        // Class: IN (0x0001)
        dos.writeShort(1)

        return baos.toByteArray()
    }

    private fun parseDnsResponse(buffer: ByteArray, len: Int): List<InetAddress> {
        val ips = mutableListOf<InetAddress>()
        try {
            val bais = ByteArrayInputStream(buffer, 0, len)
            val dis = DataInputStream(bais)

            val id = dis.readShort()
            val flags = dis.readShort()
            val qdCount = dis.readUnsignedShort()
            val anCount = dis.readUnsignedShort()
            val nsCount = dis.readUnsignedShort()
            val arCount = dis.readUnsignedShort()

            // Skip questions
            for (i in 0 until qdCount) {
                skipName(dis)
                val qType = dis.readShort()
                val qClass = dis.readShort()
            }

            // Parse Answers
            for (i in 0 until anCount) {
                skipName(dis)
                val type = dis.readUnsignedShort()
                val clazz = dis.readUnsignedShort()
                val ttl = dis.readInt()
                val rdLength = dis.readUnsignedShort()

                if (type == 1 && rdLength == 4) { // A record (IPv4)
                    val ipBytes = ByteArray(4)
                    dis.readFully(ipBytes)
                    val addr = InetAddress.getByAddress(ipBytes)
                    if (!isPoisoned(addr, "")) {
                        ips.add(addr)
                    }
                } else {
                    dis.skipBytes(rdLength)
                }
            }
        } catch (e: Exception) {
            Log.e("RobustResolver", "Failed to parse DNS response", e)
        }
        return ips
    }

    private fun skipName(dis: DataInputStream) {
        var len = dis.readUnsignedByte()
        while (len != 0) {
            if ((len and 0xC0) == 0xC0) {
                // Compression pointer (2 bytes total, we already read 1)
                dis.readByte()
                break
            } else {
                dis.skipBytes(len)
                len = dis.readUnsignedByte()
            }
        }
    }
}
