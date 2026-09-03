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
    suspend fun queryDohOverQuic(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> {
        try {
            val engine = com.aistudio.pinkproxy.fresh.cronet.CronetEngineProvider.getEngine()
            if (engine != null) {
                val transport = com.aistudio.pinkproxy.fresh.cronet.CronetDohTransport(engine)
                val queryId = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
                val query = DnsPacketEngine.buildDnsQuery(host, type, id = queryId)
                
                // Construct DoH URL from dnsIp or use default
                val url = if (dnsIp.startsWith("http")) dnsIp else "https://$dnsIp/dns-query"
                
                val responseBytes = transport.resolveDoH(url, query)
                if (responseBytes != null && responseBytes.isNotEmpty()) {
                    return DnsPacketEngine.parseDnsResponse(responseBytes, responseBytes.size, expectedId = queryId, expectedHost = host)
                }
            }
            // Fallback if Cronet is not available or fails
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
            socket = ProtectedSocketFactory.createProtectedDatagramSocket(vpnService)
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
            socket = ProtectedSocketFactory.createProtectedDatagramSocket(vpnService)
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
            socket = ProtectedSocketFactory.createProtectedDatagramSocket(vpnService)
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
        try {
            repeat(resolvers.size) {
                val res = channel.receive()
                if (res.isNotEmpty() && result.isEmpty()) {
                    result = res
                    coroutineContext.cancelChildren()
                    return@coroutineScope result
                }
            }
        } finally {
            channel.close()
        }
        result
    }

    suspend fun queryUdpDnsShadow(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        var socket: java.net.DatagramSocket? = null
        try {
            socket = ProtectedSocketFactory.createProtectedDatagramSocket(vpnService)
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
    private fun readFully(inputStream: java.io.InputStream, buffer: ByteArray, length: Int): Boolean {
        var totalRead = 0
        while (totalRead < length) {
            val r = inputStream.read(buffer, totalRead, length - totalRead)
            if (r == -1) return false
            totalRead += r
        }
        return true
    }

    suspend fun queryTcpDnsShadow(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        var socket: java.net.Socket? = null
        try {
            socket = ProtectedSocketFactory.createProtectedSocket(vpnService)
            socket.tcpNoDelay = true
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
            if (length <= 0 || length > 65535) return@withContext emptyList<InetAddress>()
            
            val response = ByteArray(length)
            if (!readFully(isInput, response, length)) return@withContext emptyList<InetAddress>()
            DnsPacketEngine.parseDnsResponse(response, length, expectedId = queryId, expectedHost = host)
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
        try {
            repeat(resolvers.size) {
                val res = channel.receive()
                if (res.isNotEmpty() && result.isEmpty()) {
                    result = res
                    coroutineContext.cancelChildren()
                    return@coroutineScope result
                }
            }
        } finally {
            channel.close()
        }
        result
    }

    suspend fun queryTcpDns(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = queryDnsOverTcp(host, dnsIp, vpnService, type)
    
    suspend fun queryDnsOverTcp(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        var socket: java.net.Socket? = null
        try {
            socket = ProtectedSocketFactory.createProtectedSocket(vpnService)
            socket.tcpNoDelay = true
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
            if (length <= 0 || length > 65535) return@withContext emptyList<InetAddress>()
            
            val response = ByteArray(length)
            if (!readFully(isInput, response, length)) return@withContext emptyList<InetAddress>()
            DnsPacketEngine.parseDnsResponse(response, length, expectedId = queryId, expectedHost = host)
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
        val queryCtx = DnsPacketEngine.buildQueryContext(host, type)
        
        // 1. Try Cronet (QUIC/HTTP3) if available
        val engine = com.aistudio.pinkproxy.fresh.cronet.CronetEngineProvider.getEngine()
        if (engine != null) {
            try {
                val transport = com.aistudio.pinkproxy.fresh.cronet.CronetDohTransport(engine)
                val body = transport.resolveDoH(dohUrl, queryCtx.rawBytes)
                if (body != null) {
                    val records = DnsPacketEngine.parseDnsResponseDetailed(body, body.size, expectedId = queryCtx.id, expectedHost = queryCtx.host)
                    if (records.isNotEmpty()) {
                        DnsOptimizer.recordDohSuccess(dohUrl)
                        return@withContext records
                    }
                }
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                Log.w("DohDnsProtocols", "Cronet DoH failed or parse error, falling back to OkHttp: ${e.message}")
                // If the error was from Cronet itself (network issue), we fallback to OkHttp TCP pipeline.
                // CronetMetrics.recordFallbackToTcp() is already recorded in onResponseStarted if it negotiated HTTP/2.
                // But if it's a total failure, we record fallback here.
                if (e !is java.lang.IllegalArgumentException) { // Assuming parse errors are IllegalArg or similar
                    com.aistudio.pinkproxy.fresh.cronet.CronetMetrics.recordFallbackToTcp()
                }
            }
        }

        // 2. Fallback to existing OkHttp pipeline (HTTP/2 / TCP)
        try {
            val client = DnsProtocols.getProtectedClient(vpnService)
            val request = Request.Builder()
                .url(dohUrl)
                .post(queryCtx.rawBytes.toRequestBody("application/dns-message".toMediaTypeOrNull()))
                .header("Accept", "application/dns-message")
                .build()
            
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    DnsOptimizer.recordDohFailure(dohUrl)
                    return@withContext emptyList<DnsPacketEngine.DnsRecord>()
                }
                val body = response.body?.bytes()
                if (body == null) {
                    DnsOptimizer.recordDohFailure(dohUrl)
                    return@withContext emptyList<DnsPacketEngine.DnsRecord>()
                }
                val records = DnsPacketEngine.parseDnsResponseDetailed(body, body.size, expectedId = queryCtx.id, expectedHost = queryCtx.host)
                if (records.isNotEmpty()) {
                    DnsOptimizer.recordDohSuccess(dohUrl)
                } else {
                    DnsOptimizer.recordDohFailure(dohUrl)
                }
                return@withContext records
            }
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            DnsOptimizer.recordDohFailure(dohUrl)
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
        try {
            repeat(extremeEndpoints.size) {
                val res = channel.receive()
                if (res.isNotEmpty() && result.isEmpty()) {
                    result = res
                    coroutineContext.cancelChildren()
                    return@coroutineScope result
                }
            }
        } finally {
            channel.close()
        }
        result
    }

    suspend fun queryDohSmuggling(host: String, vpnService: VpnService?, type: Int): List<InetAddress> = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        try {
            val client = DnsProtocols.getProtectedClient(vpnService)
            val queryCtx = DnsPacketEngine.buildQueryContext(host, type)
            val request = Request.Builder()
                .url(DnsOptimizer.bestDohUrl)
                .post(queryCtx.rawBytes.toRequestBody("application/dns-message".toMediaTypeOrNull()))
                .header("Accept", "application/dns-message")
                .header("X-Forwarded-For", "127.0.0.1")
                .header("Cache-Control", "no-cache, no-transform")
                .build()
            
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return@withContext emptyList()
                val body = response.body?.bytes() ?: return@withContext emptyList()
                return@withContext DnsPacketEngine.parseDnsResponse(body, body.size, expectedId = queryCtx.id, expectedHost = queryCtx.host)
            }
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            emptyList()
        }
    }
}

object DotDnsProtocols {
    private val socketFactory = javax.net.ssl.SSLSocketFactory.getDefault() as javax.net.ssl.SSLSocketFactory

    private fun readFully(inputStream: java.io.InputStream, buffer: ByteArray, length: Int): Boolean {
        var totalRead = 0
        while (totalRead < length) {
            val r = inputStream.read(buffer, totalRead, length - totalRead)
            if (r == -1) return false
            totalRead += r
        }
        return true
    }

    suspend fun queryDot(host: String, dotIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        var plainSocket: java.net.Socket? = null
        var socket: java.net.Socket? = null
        try {
            plainSocket = ProtectedSocketFactory.createProtectedSocket(vpnService)
            plainSocket.tcpNoDelay = true
            plainSocket.connect(java.net.InetSocketAddress(dotIp, 853), 4000)
            
            socket = socketFactory.createSocket(plainSocket, dotIp, 853, true)
            plainSocket = null // Ownership transferred to SSLSocket with autoClose = true
            socket.soTimeout = 4000
            
            val queryCtx = DnsPacketEngine.buildQueryContextTcp(host, type)
            val os = socket.getOutputStream()
            os.write(queryCtx.rawBytes)
            os.flush()
            
            val isInput = socket.getInputStream()
            val len1 = isInput.read()
            val len2 = isInput.read()
            if (len1 == -1 || len2 == -1) return@withContext emptyList<InetAddress>()
            val length = (len1 shl 8) or len2
            if (length <= 0 || length > 65535) return@withContext emptyList<InetAddress>()
            
            val response = ByteArray(length)
            if (!readFully(isInput, response, length)) return@withContext emptyList<InetAddress>()
            val result = DnsPacketEngine.parseDnsResponse(response, length, expectedId = queryCtx.id, expectedHost = queryCtx.host)
            if (result.isNotEmpty()) {
                DnsOptimizer.recordDotSuccess(dotIp)
            } else {
                DnsOptimizer.recordDotFailure(dotIp)
            }
            result
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            DnsOptimizer.recordDotFailure(dotIp)
            Log.v("DotDnsProtocols", "DoT query failed for $host via $dotIp: ${e.message}")
            emptyList()
        } finally {
            try { plainSocket?.close() } catch (_: Exception) {}
            try { socket?.close() } catch (_: Exception) {}
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
