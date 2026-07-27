package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.HttpURLConnection
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.HostnameVerifier
import kotlinx.coroutines.*

object DnsProtocols {

    suspend fun queryUdpDns(host: String, dnsIp: String, vpnService: VpnService?): List<InetAddress> {
        val id = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
        val query = DnsPacketEngine.buildDnsQuery(host, 1, id)
        val socket = DatagramSocket()
        try {
            vpnService?.protect(socket)
            socket.soTimeout = 3000
            val packet = DatagramPacket(query, query.size, InetAddress.getByName(dnsIp), 53)
            socket.send(packet)
            
            val buffer = ByteArray(1024)
            val respPacket = DatagramPacket(buffer, buffer.size)
            socket.receive(respPacket)
            val ips = DnsPacketEngine.parseDnsResponse(respPacket.data, respPacket.length, id)
            return ips.filter { !DnsCacheManager.isPoisoned(it, host) }
        } finally {
            try { socket.close() } catch (e: Exception) {}
        }
    }

    suspend fun queryUdpDnsShadow(host: String, dnsIp: String, vpnService: VpnService?): List<InetAddress> {
        val idReal = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
        val idFake = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
        val queryReal = DnsPacketEngine.buildDnsQuery(host, 1, idReal)
        
        val innocentDomains = listOf("google.com", "bing.com", "apple.com", "microsoft.com", "cloudflare.com")
        val fakeDomain = innocentDomains.random()
        val queryFake = DnsPacketEngine.buildDnsQuery(fakeDomain, 1, idFake)
        
        val socket = DatagramSocket()
        try {
            vpnService?.protect(socket)
            socket.soTimeout = 3000
            val dnsAddr = InetAddress.getByName(dnsIp)
            
            // Send fake query to innocent host with different ID
            socket.send(DatagramPacket(queryFake, queryFake.size, dnsAddr, 53))
            delay(java.util.concurrent.ThreadLocalRandom.current().nextLong(5, 25)) // Random interval
            socket.send(DatagramPacket(queryReal, queryReal.size, dnsAddr, 53))
            
            val buffer = ByteArray(1024)
            val start = System.currentTimeMillis()
            while (System.currentTimeMillis() - start < 3000) {
                val respPacket = DatagramPacket(buffer, buffer.size)
                try {
                    socket.receive(respPacket)
                } catch (e: Exception) { break }
                val res = DnsPacketEngine.parseDnsResponse(respPacket.data, respPacket.length, idReal)
                val clean = res.filter { !DnsCacheManager.isPoisoned(it, host) }
                if (clean.isNotEmpty()) return clean
            }
        } catch (e: Exception) {} finally {
            try { socket.close() } catch (e: Exception) {}
        }
        return emptyList()
    }

    suspend fun queryTcpDns(host: String, dnsIp: String, vpnService: VpnService?): List<InetAddress> {
        val id = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
        val query = DnsPacketEngine.buildDnsQuery(host, 1, id)
        val socket = Socket()
        try {
            vpnService?.protect(socket)
            socket.connect(InetSocketAddress(dnsIp, 53), 3000)
            socket.soTimeout = 3000
            val dos = DataOutputStream(socket.getOutputStream())
            dos.writeShort(query.size)
            dos.write(query)
            dos.flush()
            
            val dis = DataInputStream(socket.getInputStream())
            val len = dis.readUnsignedShort()
            val resp = ByteArray(len)
            dis.readFully(resp)
            val ips = DnsPacketEngine.parseDnsResponse(resp, len, id)
            return ips.filter { !DnsCacheManager.isPoisoned(it, host) }
        } finally {
            try { socket.close() } catch (e: Exception) {}
        }
    }

    suspend fun queryDot(host: String, dotIp: String, vpnService: VpnService?): List<InetAddress> {
        val id = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
        val query = DnsPacketEngine.buildDnsQuery(host, 1, id)
        val socket = SSLContext.getInstance("TLS").apply { init(null, null, null) }.socketFactory.createSocket()
        try {
            vpnService?.protect(socket)
            socket.connect(InetSocketAddress(dotIp, 853), 3000)
            socket.soTimeout = 3000
            val dos = DataOutputStream(socket.getOutputStream())
            dos.writeShort(query.size)
            dos.write(query)
            dos.flush()
            
            val dis = DataInputStream(socket.getInputStream())
            val len = dis.readUnsignedShort()
            val resp = ByteArray(len)
            dis.readFully(resp)
            val ips = DnsPacketEngine.parseDnsResponse(resp, len, id)
            return ips.filter { !DnsCacheManager.isPoisoned(it, host) }
        } catch (e: Exception) {
        } finally {
            try { socket.close() } catch (e: Exception) {}
        }
        return emptyList()
    }

    suspend fun queryDoh(host: String, dohUrl: String, vpnService: VpnService?): List<InetAddress> {
        val query = DnsPacketEngine.buildDnsQuery(host, 1)
        var conn: HttpURLConnection? = null
        try {
            val url = java.net.URL(dohUrl)
            // Bootstrap: resolve DoH hostname manually to avoid recursion or block
            val dohHost = url.host
            val dohIps = DnsCacheManager.getStaticIps(dohHost) ?: DnsCacheManager.getEmergencyFallback(dohHost)
            
            val finalUrl = if (!dohIps.isNullOrEmpty()) {
                val ipAddr = dohIps.random()
                val ipStr = ipAddr.hostAddress ?: ""
                val formattedIp = if (ipAddr is java.net.Inet6Address) "[$ipStr]" else ipStr
                if (formattedIp.isNotEmpty()) {
                    java.net.URL(dohUrl.replace(dohHost, formattedIp))
                } else {
                    url
                }
            } else {
                url
            }

            conn = finalUrl.openConnection(java.net.Proxy.NO_PROXY) as HttpURLConnection
            if (conn is HttpsURLConnection) {
                val sslContext = SSLContext.getInstance("TLS")
                sslContext.init(null, null, null)
                conn.sslSocketFactory = ProtectedSSLSocketFactory(sslContext.socketFactory, vpnService)
                // If we used IP, we MUST verify hostname
                conn.hostnameVerifier = HostnameVerifier { hostname, _ -> 
                    hostname == dohHost || hostname == finalUrl.host
                }
            }
            
            conn.connectTimeout = 4000
            conn.readTimeout = 4000
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.setRequestProperty("Host", dohHost)
            conn.setRequestProperty("Content-Type", "application/dns-message")
            conn.setRequestProperty("Accept", "application/dns-message")
            
            conn.outputStream.use { it.write(query) }
            
            if (conn.responseCode == 200) {
                val resp = conn.inputStream.use { it.readBytes() }
                val ips = DnsPacketEngine.parseDnsResponse(resp, resp.size)
                return ips.filter { !DnsCacheManager.isPoisoned(it, host) }
            }
        } catch (e: Exception) {} finally {
            try { conn?.disconnect() } catch (e: Exception) {}
        }
        return emptyList()
    }

    suspend fun queryDohRacing(host: String, vpnService: VpnService?): List<InetAddress> {
        return kotlinx.coroutines.withTimeoutOrNull(6000) {
            kotlinx.coroutines.supervisorScope {
                val allUrls = DnsOptimizer.getDohUrls()
                val urls = allUrls.shuffled().take(6)
                val channel = kotlinx.coroutines.channels.Channel<List<InetAddress>>(urls.size)
                val jobs = mutableListOf<Job>()
                
                urls.forEachIndexed { index, url ->
                    jobs += launch(Dispatchers.IO) {
                        // Staggered racing: give top 2 providers a head start
                        if (index >= 2) delay(150L * (index - 1))
                        val res = queryDoh(host, url, vpnService)
                        if (res.isNotEmpty()) {
                            channel.trySend(res)
                            DnsOptimizer.recordDohSuccess(url)
                        } else {
                            DnsOptimizer.recordDohFailure(url)
                        }
                    }
                }
                
                var result = try {
                    channel.receive()
                } catch (e: Exception) {
                    emptyList<InetAddress>()
                } finally {
                    jobs.forEach { it.cancel() }
                }
                
                // If the winner is empty (unlikely with receive()), try one more time from channel
                if (result.isEmpty()) {
                    result = channel.tryReceive().getOrNull() ?: emptyList()
                }
                result
            }
        } ?: emptyList()
    }
}

class ProtectedSSLSocketFactory(private val base: SSLSocketFactory, private val vpnService: VpnService?) : SSLSocketFactory() {
    override fun getDefaultCipherSuites() = base.defaultCipherSuites
    override fun getSupportedCipherSuites() = base.supportedCipherSuites

    override fun createSocket(s: Socket, host: String, port: Int, autoClose: Boolean): Socket {
        vpnService?.protect(s)
        val sslSocket = base.createSocket(s, host, port, autoClose)
        vpnService?.protect(sslSocket)
        return sslSocket
    }

    override fun createSocket(host: String, port: Int): Socket {
        val s = base.createSocket(host, port)
        vpnService?.protect(s)
        return s
    }

    override fun createSocket(host: String, port: Int, localHost: java.net.InetAddress, localPort: Int): Socket {
        val s = base.createSocket(host, port, localHost, localPort)
        vpnService?.protect(s)
        return s
    }

    override fun createSocket(host: java.net.InetAddress, port: Int): Socket {
        val s = base.createSocket(host, port)
        vpnService?.protect(s)
        return s
    }

    override fun createSocket(address: java.net.InetAddress, port: Int, localAddress: java.net.InetAddress, localPort: Int): Socket {
        val s = base.createSocket(address, port, localAddress, localPort)
        vpnService?.protect(s)
        return s
    }
}
