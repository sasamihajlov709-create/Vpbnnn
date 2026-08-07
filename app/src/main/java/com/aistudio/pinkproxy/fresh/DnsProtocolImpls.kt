package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import java.net.InetAddress
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel

object UdpDnsProtocols {
    suspend fun queryDnsOverQuic(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = emptyList() // Complex to implement without lib
    suspend fun queryUdpDnsDetailed(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<DnsPacketEngine.DnsRecord> = emptyList()
    suspend fun queryUdpDnsReorder(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = emptyList()
    
    suspend fun queryUdpDns(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        var socket: java.net.DatagramSocket? = null
        try {
            socket = java.net.DatagramSocket()
            vpnService?.protect(socket)
            socket.soTimeout = 3000
            
            val query = DnsPacketEngine.buildDnsQuery(host, type)
            val packet = java.net.DatagramPacket(query, query.size, InetAddress.getByName(dnsIp), 53)
            socket.send(packet)
            
            val responseBuf = ByteArray(4096)
            val responsePacket = java.net.DatagramPacket(responseBuf, responseBuf.size)
            socket.receive(responsePacket)
            
            DnsPacketEngine.parseDnsResponse(responseBuf, responsePacket.length)
        } catch (e: Exception) {
            emptyList()
        } finally {
            socket?.close()
        }
    }

    suspend fun queryUdpDnsNuclear(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = queryUdpDns(host, dnsIp, vpnService, type)
    suspend fun queryUdpDnsShadow(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = queryUdpDns(host, dnsIp, vpnService, type)
}

object TcpDnsProtocols {
    suspend fun queryTcpDnsShadow(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = queryDnsOverTcp(host, dnsIp, vpnService, type)
    suspend fun queryTcpDnsNuclear(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = queryDnsOverTcp(host, dnsIp, vpnService, type)
    suspend fun queryTcpDns(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = queryDnsOverTcp(host, dnsIp, vpnService, type)
    
    suspend fun queryDnsOverTcp(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        var socket: java.net.Socket? = null
        try {
            socket = java.net.Socket()
            vpnService?.protect(socket)
            socket.connect(java.net.InetSocketAddress(dnsIp, 53), 5000)
            socket.soTimeout = 5000
            
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
            emptyList()
        } finally {
            try { socket?.close() } catch (e: Exception) {}
        }
    }
}

object DohDnsProtocols {
    private val racingUrls = listOf(
        "https://dns.google/dns-query",
        "https://1.1.1.1/dns-query",
        "https://9.9.9.9/dns-query",
        "https://dns.quad9.net/dns-query"
    )

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
            emptyList()
        }
    }

    suspend fun queryDoh(host: String, dohUrl: String, vpnService: VpnService?, type: Int): List<InetAddress> {
        return queryDohDetailed(host, dohUrl, vpnService, type).map { it.address }
    }

    suspend fun queryHttpsRecord(host: String, vpnService: VpnService?): List<DnsPacketEngine.DnsRecord> {
        return queryDohDetailed(host, "https://dns.google/dns-query", vpnService, 65)
    }

    suspend fun queryDohJson(host: String, vpnService: VpnService?, type: Int): List<InetAddress> = emptyList() // JSON DoH is less secure

    suspend fun queryDohRacing(host: String, vpnService: VpnService?, type: Int): List<InetAddress> = kotlinx.coroutines.coroutineScope {
        val selectedDns = BypassConfig.dnsType
        val urls = when (selectedDns) {
            DnsType.GOOGLE_DOH -> listOf("https://dns.google/dns-query")
            DnsType.CLOUDFLARE_DOH -> listOf("https://1.1.1.1/dns-query")
            DnsType.QUAD9_DOH -> listOf("https://9.9.9.9/dns-query")
            DnsType.CUSTOM_DOH -> listOf(BypassConfig.customDnsUrl)
            else -> racingUrls
        }

        val channel = kotlinx.coroutines.channels.Channel<List<InetAddress>>(urls.size)
        urls.forEach { url ->
            launch {
                try {
                    val res = queryDoh(host, url, vpnService, type)
                    channel.send(res)
                } catch (e: Exception) {
                    channel.send(emptyList())
                }
            }
        }
        
        var result = emptyList<InetAddress>()
        repeat(urls.size) {
            val res = channel.receive()
            if (res.isNotEmpty()) {
                result = res
                coroutineContext.cancelChildren()
                return@coroutineScope result
            }
        }
        result
    }

    suspend fun queryDohExtreme(host: String, vpnService: VpnService?, type: Int): List<InetAddress> = queryDohRacing(host, vpnService, type)
    suspend fun queryDohSmuggling(host: String, vpnService: VpnService?, type: Int): List<InetAddress> = queryDohRacing(host, vpnService, type)
}

object DotDnsProtocols {
    fun clearPool() {}
    suspend fun queryDot(host: String, dotIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = emptyList()
}
