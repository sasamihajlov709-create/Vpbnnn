package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import java.net.InetAddress
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel

object UdpDnsProtocols {
    suspend fun queryDnsOverQuic(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> {
        try {
            val dotRes = DotDnsProtocols.queryDot(host, dnsIp, vpnService, type)
            if (dotRes.isNotEmpty()) return dotRes
            return DohDnsProtocols.queryDohRacing(host, vpnService, type)
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            return emptyList()
        }
    }
    suspend fun queryUdpDnsDetailed(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<DnsPacketEngine.DnsRecord> = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        var socket: java.net.DatagramSocket? = null
        try {
            socket = java.net.DatagramSocket()
            vpnService?.protect(socket)
            socket.soTimeout = 3000
            
            val queryId = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
            val query = DnsPacketEngine.buildDnsQuery(host, type, id = queryId)
            val packet = java.net.DatagramPacket(query, query.size, InetAddress.getByName(dnsIp), 53)
            socket.send(packet)
            
            val responseBuf = ByteArray(4096)
            val responsePacket = java.net.DatagramPacket(responseBuf, responseBuf.size)
            socket.receive(responsePacket)
            
            DnsPacketEngine.parseDnsResponseDetailed(responseBuf, responsePacket.length, expectedId = queryId, expectedHost = host)
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            emptyList()
        } finally {
            socket?.close()
        }
    }
    suspend fun queryUdpDnsReorder(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        var socket: java.net.DatagramSocket? = null
        try {
            socket = java.net.DatagramSocket()
            vpnService?.protect(socket)
            socket.soTimeout = 3000
            
            val queryId = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
            val query = DnsPacketEngine.buildDnsQuery(host, type, id = queryId)
            val fake = DnsPacketEngine.buildDnsQuery("google.com", 1)
            val fakePacket = java.net.DatagramPacket(fake, fake.size, InetAddress.getByName(dnsIp), 53)
            socket.send(fakePacket)
            delay(10)
            
            val packet = java.net.DatagramPacket(query, query.size, InetAddress.getByName(dnsIp), 53)
            socket.send(packet)
            
            val responseBuf = ByteArray(4096)
            val responsePacket = java.net.DatagramPacket(responseBuf, responseBuf.size)
            socket.receive(responsePacket)
            
            DnsPacketEngine.parseDnsResponse(responseBuf, responsePacket.length, expectedId = queryId, expectedHost = host)
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            emptyList()
        } finally {
            socket?.close()
        }
    }
    
    suspend fun queryUdpDns(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        var socket: java.net.DatagramSocket? = null
        try {
            socket = java.net.DatagramSocket()
            vpnService?.protect(socket)
            socket.soTimeout = 3000
            
            val queryId = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
            val query = DnsPacketEngine.buildDnsQuery(host, type, id = queryId)
            val packet = java.net.DatagramPacket(query, query.size, InetAddress.getByName(dnsIp), 53)
            socket.send(packet)
            
            val responseBuf = ByteArray(4096)
            val responsePacket = java.net.DatagramPacket(responseBuf, responseBuf.size)
            socket.receive(responsePacket)
            
            DnsPacketEngine.parseDnsResponse(responseBuf, responsePacket.length, expectedId = queryId, expectedHost = host)
        } catch (e: java.net.SocketTimeoutException) {
            emptyList()
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            Log.v("UdpDnsProtocols", "UDP DNS query failed for $host via $dnsIp: ${e.message}")
            emptyList()
        } finally {
            socket?.close()
        }
    }

    suspend fun queryUdpDnsNuclear(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = kotlinx.coroutines.coroutineScope {
        val resolvers = listOf(dnsIp, "8.8.8.8", "1.1.1.1", "9.9.9.9").distinct()
        val channel = kotlinx.coroutines.channels.Channel<List<InetAddress>>(resolvers.size)
        resolvers.forEach { ip ->
            launch {
                try {
                    val res = queryUdpDns(host, ip, vpnService, type)
                    channel.send(res)
                } catch (e: Exception) {
                    channel.send(emptyList())
                }
            }
        }
        var result = emptyList<InetAddress>()
        repeat(resolvers.size) {
            val res = channel.receive()
            if (res.isNotEmpty() && result.isEmpty()) {
                result = res
                coroutineContext.cancelChildren()
                return@coroutineScope result
            }
        }
        result
    }

    suspend fun queryUdpDnsShadow(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        var socket: java.net.DatagramSocket? = null
        try {
            socket = java.net.DatagramSocket()
            vpnService?.protect(socket)
            socket.soTimeout = 3000
            
            // Send shadow packet with low TTL or fake query first to desync stateful firewall state
            val shadowQuery = DnsPacketEngine.buildDnsQuery("shadow.internal.net", 1)
            val shadowPacket = java.net.DatagramPacket(shadowQuery, shadowQuery.size, InetAddress.getByName(dnsIp), 53)
            socket.send(shadowPacket)
            kotlinx.coroutines.delay(5)

            val queryId = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
            val query = DnsPacketEngine.buildDnsQuery(host, type, id = queryId)
            val packet = java.net.DatagramPacket(query, query.size, InetAddress.getByName(dnsIp), 53)
            socket.send(packet)
            
            val responseBuf = ByteArray(4096)
            val responsePacket = java.net.DatagramPacket(responseBuf, responseBuf.size)
            socket.receive(responsePacket)
            
            DnsPacketEngine.parseDnsResponse(responseBuf, responsePacket.length, expectedId = queryId, expectedHost = host)
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            emptyList()
        } finally {
            socket?.close()
        }
    }
}

object TcpDnsProtocols {
    suspend fun queryTcpDnsShadow(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        var socket: java.net.Socket? = null
        try {
            socket = java.net.Socket()
            vpnService?.protect(socket)
            socket.connect(java.net.InetSocketAddress(dnsIp, 53), 4000)
            socket.soTimeout = 4000
            
            val queryId = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
            val query = DnsPacketEngine.buildDnsQueryTcp(host, type, id = queryId)
            val os = socket.getOutputStream()
            // TCP fragmentation: Write length prefix separately to desync DPI inspection
            if (query.size > 2) {
                os.write(query, 0, 2)
                os.flush()
                kotlinx.coroutines.delay(5)
                os.write(query, 2, query.size - 2)
            } else {
                os.write(query)
            }
            os.flush()
            
            val isInput = socket.getInputStream()
            val len1 = isInput.read()
            val len2 = isInput.read()
            if (len1 == -1 || len2 == -1) return@withContext emptyList<InetAddress>()
            val length = (len1 shl 8) or len2
            
            val response = ByteArray(length)
            var read = 0
            while (read < length) {
                val r = isInput.read(response, read, length - read)
                if (r == -1) break
                read += r
            }
            DnsPacketEngine.parseDnsResponse(response, read, expectedId = queryId, expectedHost = host)
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            emptyList()
        } finally {
            try { socket?.close() } catch (_: Exception) {}
        }
    }

    suspend fun queryTcpDnsNuclear(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = kotlinx.coroutines.coroutineScope {
        val resolvers = listOf(dnsIp, "8.8.8.8", "1.1.1.1").distinct()
        val channel = kotlinx.coroutines.channels.Channel<List<InetAddress>>(resolvers.size)
        resolvers.forEach { ip ->
            launch {
                try {
                    val res = queryDnsOverTcp(host, ip, vpnService, type)
                    channel.send(res)
                } catch (e: Exception) {
                    channel.send(emptyList())
                }
            }
        }
        var result = emptyList<InetAddress>()
        repeat(resolvers.size) {
            val res = channel.receive()
            if (res.isNotEmpty() && result.isEmpty()) {
                result = res
                coroutineContext.cancelChildren()
                return@coroutineScope result
            }
        }
        result
    }

    suspend fun queryTcpDns(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = queryDnsOverTcp(host, dnsIp, vpnService, type)
    
    suspend fun queryDnsOverTcp(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        var socket: java.net.Socket? = null
        try {
            socket = java.net.Socket()
            vpnService?.protect(socket)
            socket.connect(java.net.InetSocketAddress(dnsIp, 53), 5000)
            socket.soTimeout = 5000
            
            val queryId = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
            val query = DnsPacketEngine.buildDnsQueryTcp(host, type, id = queryId)
            val os = socket.getOutputStream()
            os.write(query)
            os.flush()
            
            val isInput = socket.getInputStream()
            val len1 = isInput.read()
            val len2 = isInput.read()
            if (len1 == -1 || len2 == -1) return@withContext emptyList<InetAddress>()
            val length = (len1 shl 8) or len2
            
            val response = ByteArray(length)
            var read = 0
            while (read < length) {
                val r = isInput.read(response, read, length - read)
                if (r == -1) break
                read += r
            }
            DnsPacketEngine.parseDnsResponse(response, read, expectedId = queryId, expectedHost = host)
        } catch (e: java.net.SocketTimeoutException) {
            emptyList()
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            Log.v("TcpDnsProtocols", "TCP DNS query failed for $host via $dnsIp: ${e.message}")
            emptyList()
        } finally {
            try { socket?.close() } catch (e: Exception) { Log.v("TcpDnsProtocols", "Socket close error: ${e.message}") }
        }
    }
}

object DohDnsProtocols {
    suspend fun queryDohDetailed(host: String, dohUrl: String, vpnService: VpnService?, type: Int): List<DnsPacketEngine.DnsRecord> = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        try {
            val client = DnsProtocols.getProtectedClient(vpnService)
            val query = DnsPacketEngine.buildDnsQuery(host, type)
            val request = Request.Builder()
                .url(dohUrl)
                .post(query.toRequestBody("application/dns-message".toMediaTypeOrNull()))
                .header("Accept", "application/dns-message")
                .build()
            
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return@withContext emptyList<DnsPacketEngine.DnsRecord>()
                val body = response.body?.bytes() ?: return@withContext emptyList<DnsPacketEngine.DnsRecord>()
                return@withContext DnsPacketEngine.parseDnsResponseDetailed(body, body.size)
            }
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            Log.v("DohDnsProtocols", "DoH query failed for $host via $dohUrl: ${e.message}")
            emptyList()
        }
    }

    suspend fun queryDoh(host: String, dohUrl: String, vpnService: VpnService?, type: Int): List<InetAddress> {
        return queryDohDetailed(host, dohUrl, vpnService, type).map { it.address }
    }

    suspend fun queryHttpsRecord(host: String, vpnService: VpnService?): List<DnsPacketEngine.DnsRecord> {
        if (BypassConfig.filterEch) {
            // ECH records (Type 65 HTTPS) cause TSPU RST drops on TLS handshakes.
            // Returning empty list forces browsers/clients to safely fall back to standard TLS 1.3
            // with plain SNI, allowing our advanced Zapret & SNI-split bypass to work seamlessly.
            return emptyList()
        }
        return queryDohDetailed(host, DnsOptimizer.bestDohUrl, vpnService, 65)
    }

    suspend fun queryDohJson(host: String, vpnService: VpnService?, type: Int): List<InetAddress> {
        return queryDoh(host, DnsOptimizer.bestDohUrl, vpnService, type)
    }

    suspend fun queryDohRacing(host: String, vpnService: VpnService?, type: Int): List<InetAddress> {
        return DohRacingMesh.raceDoH(host, vpnService, type)
    }

    suspend fun queryDohExtreme(host: String, vpnService: VpnService?, type: Int): List<InetAddress> = kotlinx.coroutines.coroutineScope {
        val extremeEndpoints = listOf(
            "https://dns.google/dns-query",
            "https://1.1.1.1/dns-query",
            "https://9.9.9.9/dns-query",
            "https://dns.adguard-dns.com/dns-query",
            "https://cloudflare-dns.com/dns-query"
        )
        val channel = Channel<List<InetAddress>>(extremeEndpoints.size)
        extremeEndpoints.forEach { url ->
            launch {
                try {
                    val res = queryDoh(host, url, vpnService, type)
                    channel.send(res)
                } catch (e: Exception) {
                    if (e is CancellationException) throw e
                    channel.send(emptyList())
                }
            }
        }
        var result = emptyList<InetAddress>()
        repeat(extremeEndpoints.size) {
            val res = channel.receive()
            if (res.isNotEmpty() && result.isEmpty()) {
                result = res
                coroutineContext.cancelChildren()
                return@coroutineScope result
            }
        }
        result
    }

    suspend fun queryDohSmuggling(host: String, vpnService: VpnService?, type: Int): List<InetAddress> = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        try {
            val client = DnsProtocols.getProtectedClient(vpnService)
            val query = DnsPacketEngine.buildDnsQuery(host, type)
            val request = Request.Builder()
                .url(DnsOptimizer.bestDohUrl)
                .post(query.toRequestBody("application/dns-message".toMediaTypeOrNull()))
                .header("Accept", "application/dns-message")
                .header("X-Forwarded-For", "127.0.0.1")
                .header("Cache-Control", "no-cache, no-transform")
                .build()
            
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return@withContext queryDohRacing(host, vpnService, type)
                val body = response.body?.bytes() ?: return@withContext emptyList()
                return@withContext DnsPacketEngine.parseDnsResponse(body, body.size)
            }
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            queryDohRacing(host, vpnService, type)
        }
    }
}

object DotDnsProtocols {
    private val socketFactory = javax.net.ssl.SSLSocketFactory.getDefault() as javax.net.ssl.SSLSocketFactory

    suspend fun queryDot(host: String, dotIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        var socket: java.net.Socket? = null
        try {
            val plainSocket = java.net.Socket()
            vpnService?.protect(plainSocket)
            plainSocket.connect(java.net.InetSocketAddress(dotIp, 853), 4000)
            
            socket = socketFactory.createSocket(plainSocket, dotIp, 853, true)
            socket.soTimeout = 4000
            
            val query = DnsPacketEngine.buildDnsQueryTcp(host, type)
            val os = socket.getOutputStream()
            os.write(query)
            os.flush()
            
            val isInput = socket.getInputStream()
            val len1 = isInput.read()
            val len2 = isInput.read()
            if (len1 == -1 || len2 == -1) return@withContext emptyList<InetAddress>()
            val length = (len1 shl 8) or len2
            
            val response = ByteArray(length)
            var read = 0
            while (read < length) {
                val r = isInput.read(response, read, length - read)
                if (r == -1) break
                read += r
            }
            DnsPacketEngine.parseDnsResponse(response, read)
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            Log.v("DotDnsProtocols", "DoT query failed for $host via $dotIp: ${e.message}")
            emptyList()
        } finally {
            try { socket?.close() } catch (e: Exception) {}
        }
    }

    private val socketPool = java.util.concurrent.ConcurrentHashMap<String, java.net.Socket>()

    fun clearPool() {
        socketPool.values.forEach { socket ->
            try { socket.close() } catch (e: Exception) {}
        }
        socketPool.clear()
    }
}
