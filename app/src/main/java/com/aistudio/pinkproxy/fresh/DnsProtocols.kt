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

import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit
import java.util.UUID

object DnsProtocols {

    private val baseOkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .writeTimeout(5, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .connectionPool(ConnectionPool(15, 5, TimeUnit.MINUTES))
            .build()
    }

    private var cachedProtectedClient: OkHttpClient? = null
    private var lastVpnService: VpnService? = null

    private fun getProtectedClient(vpnService: VpnService?): OkHttpClient {
        val cached = cachedProtectedClient
        if (cached != null && lastVpnService == vpnService) {
            return cached
        }
        
        val builder = baseOkHttpClient.newBuilder()
            .socketFactory(ProtectedSocketFactory(vpnService))
            .dns(BootstrapDns())
        
        try {
            val trustManagerFactory = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm())
            trustManagerFactory.init(null as java.security.KeyStore?)
            val trustManagers = trustManagerFactory.trustManagers
            val defaultTrustManager = trustManagers.firstOrNull { it is javax.net.ssl.X509TrustManager } as? javax.net.ssl.X509TrustManager
            
            if (defaultTrustManager != null) {
                val sc = SSLContext.getInstance("TLS")
                sc.init(null, arrayOf(defaultTrustManager), null)
                builder.sslSocketFactory(ProtectedSSLSocketFactory(sc.socketFactory, vpnService), defaultTrustManager)
            }
        } catch (e: Throwable) {
            Log.e("DnsProtocols", "Failed to setup protected SSL", e)
        }
        
        val client = builder.build()
        cachedProtectedClient = client
        lastVpnService = vpnService
        return client
    }

    suspend fun queryDnsOverQuic(host: String, dnsIp: String, vpnService: VpnService?): List<InetAddress> {
        val id = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
        val query = DnsPacketEngine.buildDnsQuery(host, 1, id)
        
        // Wrap DNS query in a fake QUIC Initial packet (Shadow QUIC)
        // This is highly effective because UDP:443 is usually allowed, 
        // and DPI reassembly for QUIC is complex/expensive.
        val quicPacket = FakePacketHelper.buildQuicInitialReal(
            dcid = ByteArray(8) { 0 }, 
            scid = ByteArray(8) { 0 }, 
            payload = query
        )
        
        val socket = DatagramSocket()
        val buffer = ProxyStats.obtain8k()
        try {
            try { vpnService?.protect(socket) } catch(e: Throwable) {}
            socket.soTimeout = 3000
            val targetAddr = InetAddress.getByName(dnsIp)
            socket.connect(targetAddr, 443) // Target UDP:443
            
            socket.send(DatagramPacket(quicPacket, quicPacket.size))
            
            val respPacket = DatagramPacket(buffer, buffer.size)
            socket.receive(respPacket)
            
            val data = respPacket.data
            val len = respPacket.length
            
            // Try to extract DNS response from potential shadow QUIC response
            if (len > 12) {
                // Heuristic: search for the Transaction ID in the packet if not at the start
                for (i in 0..len - 12) {
                    if (((data[i].toInt() and 0xFF) shl 8 or (data[i+1].toInt() and 0xFF)) == id) {
                         val ips = DnsPacketEngine.parseDnsResponse(data.copyOfRange(i, len), len - i, id.toInt() and 0xFFFF)
                         return ips.filter { !DnsCacheManager.isPoisoned(it, host) }
                    }
                }
            }
        } catch (e: Throwable) {
        } finally {
            ProxyStats.release8k(buffer)
            try { socket.close() } catch (e: Throwable) {}
        }
        return emptyList()
    }

    suspend fun queryUdpDnsDetailed(host: String, dnsIp: String, vpnService: VpnService?): List<DnsPacketEngine.DnsRecord> {
        val id = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
        val query = DnsPacketEngine.buildDnsQuery(host, 1, id)
        val socket = DatagramSocket()
        val buffer = ProxyStats.obtain8k()
        try {
            try { vpnService?.protect(socket) } catch(e: Throwable) {}
            socket.soTimeout = 3000
            val targetAddr = InetAddress.getByName(dnsIp)
            socket.connect(targetAddr, 53)
            val packet = DatagramPacket(query, query.size)
            socket.send(packet)
            
            val respPacket = DatagramPacket(buffer, buffer.size)
            socket.receive(respPacket)
            val records = DnsPacketEngine.parseDnsResponseDetailed(respPacket.data, respPacket.length, id)
            return records.filter { !DnsCacheManager.isPoisoned(it.address, host) }
        } catch (e: Throwable) {
            return emptyList()
        } finally {
            ProxyStats.release8k(buffer)
            try { socket.close() } catch (e: Throwable) {}
        }
    }

    suspend fun queryUdpDnsReorder(host: String, dnsIp: String, vpnService: VpnService?): List<InetAddress> {
        val id = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
        val query = DnsPacketEngine.buildDnsQuery(host, 1, id)
        val socket = DatagramSocket()
        val buffer = ProxyStats.obtain8k()
        val rnd = java.util.concurrent.ThreadLocalRandom.current()
        try {
            try { vpnService?.protect(socket) } catch(e: Throwable) {}
            socket.soTimeout = 3000
            val targetAddr = InetAddress.getByName(dnsIp)
            socket.connect(targetAddr, 53)
            
            // Send decoy query with low TTL to trick DPI, then real complete query
            TtlHelper.setUdpTtl(socket, 2, targetAddr is java.net.Inet6Address)
            val decoy = DnsPacketEngine.buildDnsQuery("check.dns.internal", 1, rnd.nextInt(0x10000))
            socket.send(DatagramPacket(decoy, decoy.size))
            delay(rnd.nextLong(1, 3))
            TtlHelper.setUdpTtl(socket, 64, targetAddr is java.net.Inet6Address)
            socket.send(DatagramPacket(query, query.size))
            
            val respPacket = DatagramPacket(buffer, buffer.size)
            socket.receive(respPacket)
            val ips = DnsPacketEngine.parseDnsResponse(respPacket.data, respPacket.length, id)
            return ips.filter { !DnsCacheManager.isPoisoned(it, host) }
        } catch (e: Throwable) {
            return emptyList()
        } finally {
            ProxyStats.release8k(buffer)
            try { socket.close() } catch (e: Throwable) {}
        }
    }

    suspend fun queryUdpDns(host: String, dnsIp: String, vpnService: VpnService?): List<InetAddress> {
        val id = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
        val query = DnsPacketEngine.buildDnsQuery(host, 1, id)
        val socket = DatagramSocket()
        val buffer = ProxyStats.obtain8k()
        try {
            try { vpnService?.protect(socket) } catch(e: Throwable) {}
            socket.soTimeout = 3000
            val targetAddr = InetAddress.getByName(dnsIp)
            socket.connect(targetAddr, 53)
            val packet = DatagramPacket(query, query.size)
            socket.send(packet)
            
            val respPacket = DatagramPacket(buffer, buffer.size)
            socket.receive(respPacket)
            // No need to check address anymore as connect() filters it
            val ips = DnsPacketEngine.parseDnsResponse(respPacket.data, respPacket.length, id)
            return ips.filter { !DnsCacheManager.isPoisoned(it, host) }
        } catch (e: Throwable) {
            return emptyList()
        } finally {
            ProxyStats.release8k(buffer)
            try { socket.close() } catch (e: Throwable) {}
        }
    }

    suspend fun queryUdpDnsNuclear(host: String, dnsIp: String, vpnService: VpnService?): List<InetAddress> {
        val id = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
        val query = DnsPacketEngine.buildDnsQuery(host, 1, id)
        val socket = DatagramSocket()
        val buffer = ProxyStats.obtain8k()
        val rnd = java.util.concurrent.ThreadLocalRandom.current()
        try {
            try { vpnService?.protect(socket) } catch(e: Throwable) {}
            socket.soTimeout = 2500
            val targetAddr = InetAddress.getByName(dnsIp)
            socket.connect(targetAddr, 53)
            val isIpv6 = targetAddr is java.net.Inet6Address
            
            // The "Nuclear" UDP Strategy:
            // 1. Multiple Low-TTL Ghost queries to saturate DPI state for this session
            repeat(rnd.nextInt(2, 4)) {
                TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5), isIpv6)
                val ghost = DnsPacketEngine.buildDnsQuery("internal.test.ghost", 1, rnd.nextInt(0x10000))
                socket.send(DatagramPacket(ghost, ghost.size))
            }
            
            // 2. High-intensity noise burst
            repeat(rnd.nextInt(3, 6)) {
                val noise = FakePacketHelper.buildUdpNoise(rnd.nextInt(16, 64))
                TtlHelper.setUdpTtl(socket, 1, isIpv6)
                socket.send(DatagramPacket(noise, noise.size))
            }
            
            TtlHelper.setUdpTtl(socket, 64, isIpv6)
            
            // 3. Duplicate real queries with slight delay to beat censorship race
            socket.send(DatagramPacket(query, query.size))
            delay(rnd.nextLong(2, 8))
            socket.send(DatagramPacket(query, query.size))
            
            val start = System.currentTimeMillis()
            while (System.currentTimeMillis() - start < 2500) {
                val respPacket = DatagramPacket(buffer, buffer.size)
                try { socket.receive(respPacket) } catch (e: Throwable) { break }
                if (respPacket.length < 12) continue
                val resId = ((respPacket.data[0].toInt() and 0xFF) shl 8) or (respPacket.data[1].toInt() and 0xFF)
                if (resId == id) {
                    val res = DnsPacketEngine.parseDnsResponse(respPacket.data, respPacket.length, id)
                    val clean = res.filter { !DnsCacheManager.isPoisoned(it, host) }
                    if (clean.isNotEmpty()) return clean
                }
            }
        } catch (e: Throwable) {
        } finally {
            ProxyStats.release8k(buffer)
            try { socket.close() } catch (e: Throwable) {}
        }
        return emptyList()
    }

    suspend fun queryUdpDnsShadow(host: String, dnsIp: String, vpnService: VpnService?): List<InetAddress> {
        val strategy = BypassConfig.getBestStrategyForHost(host)
        val mangle = strategy == BypassStrategy.DNS_CASE_MANGLE || ProxyStats.censorshipIntensity.value > 60
        
        val rnd = java.util.concurrent.ThreadLocalRandom.current()
        val idReal = rnd.nextInt(0x10000)
        val idFake = rnd.nextInt(0x10000)
        val queryReal = DnsPacketEngine.buildDnsQuery(host, 1, idReal, mangle)
        
        val innocentDomains = listOf("google.com", "bing.com", "apple.com", "microsoft.com", "cloudflare.com", "aws.amazon.com", "wikipedia.org")
        val fakeDomain = innocentDomains.random()
        val queryFake = DnsPacketEngine.buildDnsQuery(fakeDomain, 1, idFake, mangle)
        
        val socket = DatagramSocket()
        val buffer = ProxyStats.obtain8k()
        try {
            try { vpnService?.protect(socket) } catch(e: Throwable) {}
            socket.soTimeout = 2500
            val dnsAddr = InetAddress.getByName(dnsIp)
            socket.connect(dnsAddr, 53)
            
            val isIpv6 = dnsAddr is java.net.Inet6Address
            
            // 1. Ghost Query: send fake query with low TTL to poison DPI state
            TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 4), isIpv6)
            socket.send(DatagramPacket(queryFake, queryFake.size))
            delay(rnd.nextLong(1, 5))
            TtlHelper.setUdpTtl(socket, 64, isIpv6)
            
            // 2. Send low-TTL noise datagram to confuse DPI session state
            val noise = FakePacketHelper.buildUdpNoise(rnd.nextInt(16, 64))
            TtlHelper.setUdpTtl(socket, 1, isIpv6)
            socket.send(DatagramPacket(noise, noise.size))
            TtlHelper.setUdpTtl(socket, 64, isIpv6)

            // 3. Send full valid real query
            socket.send(DatagramPacket(queryReal, queryReal.size))
            
            // 3. Send full real query again just in case (race against censorship)
            delay(rnd.nextLong(5, 15))
            socket.send(DatagramPacket(queryReal, queryReal.size))
            
            val start = System.currentTimeMillis()
            while (System.currentTimeMillis() - start < 2500) {
                val respPacket = DatagramPacket(buffer, buffer.size)
                try {
                    socket.receive(respPacket)
                } catch (e: Throwable) { break }
                
                // Deep validation of response ID
                if (respPacket.length < 12) continue
                val resId = ((respPacket.data[0].toInt() and 0xFF) shl 8) or (respPacket.data[1].toInt() and 0xFF)
                if (resId == idReal) {
                    val res = DnsPacketEngine.parseDnsResponse(respPacket.data, respPacket.length, idReal)
                    val clean = res.filter { !DnsCacheManager.isPoisoned(it, host) }
                    if (clean.isNotEmpty()) return clean
                }
            }
        } catch (e: Throwable) {
        } finally {
            ProxyStats.release8k(buffer)
            try { socket.close() } catch (e: Throwable) {}
        }
        return emptyList()
    }

    suspend fun queryTcpDnsShadow(host: String, dnsIp: String, vpnService: VpnService?): List<InetAddress> {
        val id = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
        val query = DnsPacketEngine.buildDnsQuery(host, 1, id)
        val socket = Socket()
        val rnd = java.util.concurrent.ThreadLocalRandom.current()
        try {
            try { vpnService?.protect(socket) } catch(e: Throwable) {}
            socket.tcpNoDelay = true
            socket.connect(InetSocketAddress(dnsIp, 53), 4000)
            socket.soTimeout = 4000
            val output = socket.getOutputStream()
            val fullQuery = ByteArray(query.size + 2)
            fullQuery[0] = (query.size shr 8).toByte()
            fullQuery[1] = (query.size and 0xFF).toByte()
            System.arraycopy(query, 0, fullQuery, 2, query.size)
            
            // Fragmented send with fake padding
            val split = if (fullQuery.size > 4) rnd.nextInt(2, fullQuery.size - 2) else 1
            
            // Zero-Window Stall to freeze DPI buffer
            TtlHelper.setWindowSize(socket, 0)
            delay(rnd.nextLong(10, 50))
            TtlHelper.setWindowSize(socket, rnd.nextInt(4, 16)) // Force tiny initial segment
            
            output.write(fullQuery, 0, split)
            output.flush()
            delay(rnd.nextLong(1, 15))
            
            // Restore window for the rest
            TtlHelper.setWindowSize(socket, 65535)
            
            // Inject fake segment if intensity is high
            if (ProxyStats.censorshipIntensity.value > 65) {
                val fake = FakePacketHelper.buildUdpNoise(rnd.nextInt(16, 64))
                try {
                    try { socket.sendUrgentData(java.util.concurrent.ThreadLocalRandom.current().nextInt(256)) } catch(e: Throwable) {}
                    val fakeTtl = BypassConfig.fakeTtl.takeIf { it > 0 } ?: AutoTtlProber.getDiscoveredTtl(dnsIp) ?: rnd.nextInt(2, 6)
                    TtlHelper.setTtl(socket, fakeTtl)
                    output.write(fake)
                    output.flush()
                    delay(2)
                    TtlHelper.setTtl(socket, 64)
                } catch(e: Throwable) {}
            }
            
            output.write(fullQuery, split, fullQuery.size - split)
            output.flush()
            
            val dis = DataInputStream(socket.getInputStream())
            val len = dis.readUnsignedShort()
            if (len > 8192) return emptyList()
            val resp = ByteArray(len)
            dis.readFully(resp)
            val ips = DnsPacketEngine.parseDnsResponse(resp, len, id)
            return ips.filter { !DnsCacheManager.isPoisoned(it, host) }
        } catch (e: Throwable) {
        } finally {
            try { socket.close() } catch (e: Throwable) {}
        }
        return emptyList()
    }

    suspend fun queryTcpDnsNuclear(host: String, dnsIp: String, vpnService: VpnService?): List<InetAddress> {
        val id = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
        val query = DnsPacketEngine.buildDnsQuery(host, 1, id)
        val socket = Socket()
        val rnd = java.util.concurrent.ThreadLocalRandom.current()
        try {
            try { vpnService?.protect(socket) } catch(e: Throwable) {}
            socket.tcpNoDelay = true
            socket.connect(InetSocketAddress(dnsIp, 53), 5000)
            socket.soTimeout = 5000
            val output = socket.getOutputStream()
            
            val fullQuery = ByteArray(query.size + 2)
            fullQuery[0] = (query.size shr 8).toByte()
            fullQuery[1] = (query.size and 0xFF).toByte()
            System.arraycopy(query, 0, fullQuery, 2, query.size)
            
            // 1. Zero-Window Pulse to confuse DPI reassembly state
            TtlHelper.setWindowSize(socket, 0)
            delay(rnd.nextLong(20, 100))
            TtlHelper.setWindowSize(socket, rnd.nextInt(2, 8))
            
            // 2. Fragmented send with OOB and Fake TTL segments
            val split1 = 2 // Length field
            val split2 = 2 + (query.size / 2)
            
            output.write(fullQuery, 0, split1); output.flush()
            delay(rnd.nextLong(5, 15))
            
            // OOB Confusion
            try { socket.sendUrgentData(rnd.nextInt(256)) } catch(e: Throwable) {}
            
            // Fake Segment (Low TTL)
            val fakeTtl = BypassConfig.fakeTtl.takeIf { it > 0 } ?: AutoTtlProber.getDiscoveredTtl(dnsIp) ?: rnd.nextInt(2, 6)
            TtlHelper.setTtl(socket, fakeTtl)
            output.write(FakePacketHelper.buildUdpNoise(16))
            output.flush()
            delay(2)
            TtlHelper.setTtl(socket, 64)
            
            output.write(fullQuery, split1, split2 - split1); output.flush()
            delay(rnd.nextLong(5, 15))
            
            TtlHelper.setWindowSize(socket, 65535)
            output.write(fullQuery, split2, fullQuery.size - split2); output.flush()
            
            val dis = DataInputStream(socket.getInputStream())
            val len = dis.readUnsignedShort()
            if (len > 8192) return emptyList()
            val resp = ByteArray(len)
            dis.readFully(resp)
            val ips = DnsPacketEngine.parseDnsResponse(resp, len, id)
            return ips.filter { !DnsCacheManager.isPoisoned(it, host) }
        } catch (e: Throwable) {
        } finally {
            try { socket.close() } catch (e: Throwable) {}
        }
        return emptyList()
    }

    suspend fun queryTcpDns(host: String, dnsIp: String, vpnService: VpnService?): List<InetAddress> {
        val id = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
        val query = DnsPacketEngine.buildDnsQuery(host, 1, id)
        val socket = Socket()
        try {
            try { vpnService?.protect(socket) } catch(e: Throwable) {}
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
        } catch (e: Throwable) {
            return emptyList()
        } finally {
            try { socket.close() } catch (e: Throwable) {}
        }
    }

    private val dotHostnames = mapOf(
        "8.8.8.8" to "dns.google",
        "8.8.4.4" to "dns.google",
        "1.1.1.1" to "one.one.one.one",
        "1.0.0.1" to "one.one.one.one",
        "9.9.9.9" to "dns.quad9.net",
        "149.112.112.112" to "dns.quad9.net",
        "76.76.2.0" to "dns.controld.com",
        "76.76.10.0" to "dns.controld.com",
        "94.140.14.14" to "dns.adguard.com",
        "94.140.15.15" to "dns.adguard.com"
    )

    private val dotPool = java.util.concurrent.ConcurrentHashMap<String, javax.net.ssl.SSLSocket>()
    private val poolLock = Any()

    fun clearPool() {
        synchronized(poolLock) {
            dotPool.forEach { (_, socket) ->
                try { socket.close() } catch (e: Throwable) {}
            }
            dotPool.clear()
        }
    }

    suspend fun queryDot(host: String, dotIp: String, vpnService: VpnService?): List<InetAddress> {
        val id = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
        val query = DnsPacketEngine.buildDnsQuery(host, 1, id)
        
        return withContext(ProxyDispatcher.io) {
            runCatching {
                var sslSocket: javax.net.ssl.SSLSocket? = dotPool[dotIp]
                
                if (sslSocket == null || sslSocket.isClosed || !sslSocket.isConnected) {
                    synchronized(poolLock) {
                        sslSocket = dotPool[dotIp]
                        if (sslSocket == null || sslSocket!!.isClosed || !sslSocket!!.isConnected) {
                            val trustManagerFactory = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm())
                            trustManagerFactory.init(null as java.security.KeyStore?)
                            val trustManagers = trustManagerFactory.trustManagers
                            val defaultTrustManager = trustManagers.firstOrNull { it is javax.net.ssl.X509TrustManager } as? javax.net.ssl.X509TrustManager
                            
                            val sc = SSLContext.getInstance("TLS")
                            sc.init(null, if (defaultTrustManager != null) arrayOf(defaultTrustManager) else null, null)
                            
                            val factory = ProtectedSSLSocketFactory(sc.socketFactory, vpnService)
                            val s = factory.createSocket() as javax.net.ssl.SSLSocket
                            s.connect(InetSocketAddress(dotIp, 853), 4000)
                            s.soTimeout = 5000
                            s.tcpNoDelay = true
                            s.startHandshake()
                            
                            val expectedHost = dotHostnames[dotIp] ?: dotIp
                            if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(expectedHost, s.session)) {
                                s.close()
                                throw Exception("DoT hostname verification failed")
                            }
                            dotPool[dotIp] = s
                            sslSocket = s
                        }
                    }
                }

                val socket = sslSocket!!
                val dos = DataOutputStream(socket.getOutputStream())
                dos.writeShort(query.size)
                dos.write(query)
                dos.flush()
                
                val dis = DataInputStream(socket.getInputStream())
                val len = dis.readUnsignedShort()
                if (len > 8192) throw Exception("Packet too large")
                val resp = ByteArray(len)
                dis.readFully(resp)
                DnsPacketEngine.parseDnsResponse(resp, len, id).filter { !DnsCacheManager.isPoisoned(it, host) }
            }.getOrElse { 
                dotPool.remove(dotIp)?.let { try { it.close() } catch(e: Throwable) {} }
                emptyList() 
            }
        }
    }

    suspend fun queryDnsOverTcp(host: String, dnsIp: String, vpnService: VpnService?): List<InetAddress> {
        val id = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
        val query = DnsPacketEngine.buildDnsQuery(host, 1, id)
        val socket = Socket()
        val rnd = java.util.concurrent.ThreadLocalRandom.current()
        try {
            try { vpnService?.protect(socket) } catch(e: Throwable) {}
            socket.tcpNoDelay = true
            socket.connect(InetSocketAddress(dnsIp, 53), 3000)
            socket.soTimeout = 3000
            val output = socket.getOutputStream()
            
            val fullQuery = ByteArray(query.size + 2)
            fullQuery[0] = (query.size shr 8).toByte()
            fullQuery[1] = (query.size and 0xFF).toByte()
            System.arraycopy(query, 0, fullQuery, 2, query.size)
            
            // Fragment the TCP stream for the DNS query with Zero-Window pulses
            val split = if (fullQuery.size > 3) rnd.nextInt(2, fullQuery.size - 1) else 1
            
            if (ProxyStats.censorshipIntensity.value > 70) {
                TtlHelper.setWindowSize(socket, 0)
                delay(rnd.nextLong(5, 20))
                TtlHelper.setWindowSize(socket, 65535)
            }
            
            output.write(fullQuery, 0, split); output.flush()
            delay(rnd.nextLong(2, 8))
            output.write(fullQuery, split, fullQuery.size - split); output.flush()
            
            val dis = DataInputStream(socket.getInputStream())
            val len = dis.readUnsignedShort()
            if (len > 8192) return emptyList()
            val resp = ByteArray(len)
            dis.readFully(resp)
            val ips = DnsPacketEngine.parseDnsResponse(resp, len, id)
            return ips.filter { !DnsCacheManager.isPoisoned(it, host) }
        } catch (e: Throwable) {
        } finally {
            try { socket.close() } catch (e: Throwable) {}
        }
        return emptyList()
    }

    suspend fun queryDohDetailed(host: String, dohUrl: String, vpnService: VpnService?, type: Int = 1): List<DnsPacketEngine.DnsRecord> {
        val intensity = ProxyStats.censorshipIntensity.value
        val rnd = java.util.concurrent.ThreadLocalRandom.current()
        val timeout = (if (intensity > 80) 6000L else 4000L) + rnd.nextLong(0, 500)
        
        val id = rnd.nextInt(0x10000)
        val query = DnsPacketEngine.buildDnsQuery(host, type, id)
        try {
            val client = getProtectedClient(vpnService).newBuilder()
                .connectTimeout(timeout, TimeUnit.MILLISECONDS)
                .readTimeout(timeout, TimeUnit.MILLISECONDS)
                .writeTimeout(timeout, TimeUnit.MILLISECONDS)
                .build()

            val request = Request.Builder()
                .url(dohUrl)
                .post(query.toRequestBody("application/dns-message".toMediaType()))
                .header("Accept", "application/dns-message")
                .header("User-Agent", FakePacketHelper.getRandomUserAgent())
                .apply {
                    val paddingSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(64, 256)
                    header("X-Dns-Padding", java.util.Base64.getEncoder().encodeToString(ByteArray(paddingSize) { rnd.nextInt(256).toByte() }))
                    if (intensity > 50) {
                        header("X-Forwarded-For", "${rnd.nextInt(1, 255)}.${rnd.nextInt(255)}.${rnd.nextInt(255)}.${rnd.nextInt(255)}")
                        header("Cache-Control", "no-cache, no-store, must-revalidate")
                        header("Pragma", "no-cache")
                        header("Expires", "0")
                        if (rnd.nextBoolean()) header("X-Requested-With", "XMLHttpRequest")
                    }
                }
                .build()

            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val body = response.body?.bytes() ?: return emptyList()
                    val records = DnsPacketEngine.parseDnsResponseDetailed(body, body.size, id)
                    return records.filter { !DnsCacheManager.isPoisoned(it.address, host) }
                }
            }
        } catch (e: Throwable) {
        }
        return emptyList()
    }

    suspend fun queryDoh(host: String, dohUrl: String, vpnService: VpnService?): List<InetAddress> {
        return queryDohDetailed(host, dohUrl, vpnService).map { it.address }
    }

    suspend fun queryHttpsRecord(host: String, vpnService: VpnService?): List<DnsPacketEngine.DnsRecord> {
        return queryDohDetailed(host, DnsOptimizer.bestDohUrl, vpnService, 65)
    }

    suspend fun queryDohJson(host: String, vpnService: VpnService?): List<InetAddress> {
        val urls = listOf(
            "https://dns.google/resolve?name=$host&type=A",
            "https://cloudflare-dns.com/dns-query?name=$host&type=A"
        )
        val url = urls.random()
        try {
            val client = getProtectedClient(vpnService).newBuilder()
                .connectTimeout(5000, TimeUnit.MILLISECONDS)
                .build()

            val request = Request.Builder()
                .url(url)
                .header("Accept", "application/dns-json")
                .header("User-Agent", FakePacketHelper.getRandomUserAgent())
                .build()

            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val body = response.body?.string() ?: return emptyList()
                    // Simple regex based parsing for speed and to avoid adding a JSON library
                    val regex = """"data":\s*"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""".toRegex()
                    val matches = regex.findAll(body)
                    val ips = matches.mapNotNull { 
                        try { InetAddress.getByName(it.groupValues[1]) } catch(e: Throwable) { null }
                    }.toList()
                    return ips.filter { !DnsCacheManager.isPoisoned(it, host) }
                }
            }
        } catch (e: Throwable) {}
        return emptyList()
    }

    suspend fun queryDohRacing(host: String, vpnService: VpnService?): List<InetAddress> {
        return kotlinx.coroutines.withTimeoutOrNull(7000) {
            kotlinx.coroutines.supervisorScope {
                val allUrls = DnsOptimizer.getDohUrls()
                // Sort by latency, put high latency at the end. Use 5000 as default for unknown.
                val urls = allUrls.sortedBy { DnsOptimizer.getLatencyForUrl(it) }.take(8)
                val channel = kotlinx.coroutines.channels.Channel<List<InetAddress>>(urls.size)
                val jobs = mutableListOf<Job>()
                val completed = java.util.concurrent.atomic.AtomicInteger(0)
                
                urls.forEachIndexed { index, url ->
                    jobs += launch(ProxyDispatcher.io) {
                        try {
                            // Staggered racing: give top providers a small head start
                            val delayMs = when {
                                index == 0 -> 0L
                                index == 1 -> 50L
                                else -> 100L * (index - 1)
                            }
                            if (delayMs > 0) delay(delayMs)
                            
                            val res = queryDoh(host, url, vpnService)
                            if (res.isNotEmpty()) {
                                channel.trySend(res)
                                DnsOptimizer.recordDohSuccess(url)
                            } else {
                                DnsOptimizer.recordDohFailure(url)
                            }
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Throwable) {
                            DnsOptimizer.recordDohFailure(url)
                        } finally {
                            if (completed.incrementAndGet() == urls.size) {
                                channel.close()
                            }
                        }
                    }
                }
                
                var result = emptyList<InetAddress>()
                try {
                    result = channel.receive()
                } catch (e: Throwable) {
                    // All failed or timeout
                } finally {
                    jobs.forEach { it.cancel() }
                }
                
                result
            }
        } ?: emptyList()
    }

    suspend fun queryDohExtreme(host: String, vpnService: VpnService?): List<InetAddress> {
        val hardcodedIps = listOf(
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query",
            "https://9.9.9.9/dns-query",
            "https://1.0.0.1/dns-query",
            "https://8.8.4.4/dns-query"
        )
        return supervisorScope {
            val channel = kotlinx.coroutines.channels.Channel<List<InetAddress>>(hardcodedIps.size)
            val completed = java.util.concurrent.atomic.AtomicInteger(0)
            val jobs = hardcodedIps.map { url ->
                launch(ProxyDispatcher.io) {
                    try {
                        val res = queryDoh(host, url, vpnService)
                        if (res.isNotEmpty()) channel.trySend(res)
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Throwable) {
                    } finally {
                        if (completed.incrementAndGet() == hardcodedIps.size) {
                            channel.close()
                        }
                    }
                }
            }
            val result = try {
                withTimeoutOrNull(5000) { channel.receive() } ?: emptyList()
            } catch (e: Throwable) {
                emptyList()
            }
            jobs.forEach { it.cancel() }
            result
        }
    }

    suspend fun queryDohSmuggling(host: String, vpnService: VpnService?): List<InetAddress> {
        val id = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
        val query = DnsPacketEngine.buildDnsQuery(host, 1, id)
        val rnd = java.util.concurrent.ThreadLocalRandom.current()
        
        // Use a rotating set of popular IPs that often host DoH or are on popular CDNs
        val targets = listOf("1.1.1.1", "8.8.8.8", "9.9.9.9", "104.16.249.249", "104.16.248.249", "149.112.112.112")
        val target = targets.random()
        
        val trustManagerFactory = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm())
        trustManagerFactory.init(null as java.security.KeyStore?)
        val trustManagers = trustManagerFactory.trustManagers
        val defaultTrustManager = trustManagers.firstOrNull { it is javax.net.ssl.X509TrustManager } as? javax.net.ssl.X509TrustManager
        
        val sc = SSLContext.getInstance("TLS")
        sc.init(null, if (defaultTrustManager != null) arrayOf(defaultTrustManager) else null, null)
        
        val factory = ProtectedSSLSocketFactory(sc.socketFactory, vpnService)
        val sslSocket = factory.createSocket() as? javax.net.ssl.SSLSocket ?: return emptyList()
        
        try {
            sslSocket.connect(InetSocketAddress(target, 443), 4000)
            sslSocket.soTimeout = 4000
            
            // Set SNI to a very common innocent domain to bypass SNI-based blocking
            val innocentSni = listOf("google.com", "microsoft.com", "apple.com", "cloudflare.com").random()
            try {
                val sslParameters = sslSocket.sslParameters
                sslParameters.serverNames = listOf(javax.net.ssl.SNIHostName(innocentSni))
                sslSocket.sslParameters = sslParameters
            } catch (e: Throwable) {}
            
            sslSocket.startHandshake()
            
            val output = sslSocket.getOutputStream()
            val input = sslSocket.getInputStream()
            
            val hostHeader = if (target == "1.1.1.1" || target.startsWith("104.")) "cloudflare-dns.com" else "dns.google"
            
            val sb = StringBuilder()
            sb.append("POST /dns-query HTTP/1.1\r\n")
            sb.append("Host: ").append(hostHeader).append("\r\n")
            sb.append("Content-Type: application/dns-message\r\n")
            sb.append("Content-Length: ").append(query.size).append("\r\n")
            sb.append("Accept: application/dns-message\r\n")
            sb.append("User-Agent: ").append(FakePacketHelper.getRandomUserAgent()).append("\r\n")
            sb.append("Connection: close\r\n")
            
            // Add junk headers to confuse pattern matching
            repeat(rnd.nextInt(2, 5)) {
                sb.append("X-").append(UUID.randomUUID().toString().take(8)).append(": ").append(UUID.randomUUID().toString()).append("\r\n")
            }
            
            sb.append("\r\n")
            
            output.write(sb.toString().toByteArray())
            output.flush()
            
            // Write query in fragments to avoid detection of DNS-over-HTTPS patterns in a single packet
            if (query.size <= 1) return emptyList()
            val split = rnd.nextInt(1, query.size)
            output.write(query, 0, split); output.flush()
            delay(rnd.nextLong(5, 20))
            output.write(query, split, query.size - split); output.flush()
            
            val dis = DataInputStream(input)
            val headerBuffer = StringBuilder()
            var lastChar = ' '
            while (true) {
                val b = dis.read()
                if (b == -1) break
                val c = b.toChar()
                headerBuffer.append(c)
                if (c == '\n' && lastChar == '\r' && headerBuffer.endsWith("\r\n\r\n")) break
                lastChar = c
                if (headerBuffer.length > 4096) break
            }
            
            // Simple check for 200 OK
            if (headerBuffer.contains("200 OK")) {
                // Find content length or read until EOF since we sent Connection: close
                val body = dis.readBytes()
                if (body.isNotEmpty()) {
                    val ips = DnsPacketEngine.parseDnsResponse(body, body.size, id)
                    return ips.filter { !DnsCacheManager.isPoisoned(it, host) }
                }
            }
        } catch (e: Throwable) {
        } finally {
            try { sslSocket.close() } catch (e: Throwable) {}
        }
        return emptyList()
    }

    suspend fun queryDnsExtremeRacing(host: String, vpnService: VpnService?): List<InetAddress> {
        return kotlinx.coroutines.withTimeoutOrNull(6000) {
            kotlinx.coroutines.supervisorScope {
                val channel = kotlinx.coroutines.channels.Channel<List<InetAddress>>(10)
                val completed = java.util.concurrent.atomic.AtomicInteger(0)
                val totalTasks = 6
                
                // 1. DoH Racing (Top 3)
                launch(ProxyDispatcher.io) {
                    try {
                        val res = queryDohRacing(host, vpnService)
                        if (res.isNotEmpty()) channel.trySend(res)
                    } finally {
                        if (completed.incrementAndGet() == totalTasks) channel.close()
                    }
                }
                
                // 2. DoT Racing (Top 2)
                launch(ProxyDispatcher.io) {
                    try {
                        val dotIp = DnsOptimizer.bestDotServer
                        val res = queryDot(host, dotIp, vpnService)
                        if (res.isNotEmpty()) channel.trySend(res)
                    } finally {
                        if (completed.incrementAndGet() == totalTasks) channel.close()
                    }
                }
                
                // 3. Shadow DoQ (UDP:443)
                launch(ProxyDispatcher.io) {
                    try {
                        val res = queryDnsOverQuic(host, "8.8.8.8", vpnService)
                        if (res.isNotEmpty()) channel.trySend(res)
                    } finally {
                        if (completed.incrementAndGet() == totalTasks) channel.close()
                    }
                }
                
                // 4. UDP Nuclear (DNS:53)
                launch(ProxyDispatcher.io) {
                    try {
                        val res = queryUdpDnsNuclear(host, "1.1.1.1", vpnService)
                        if (res.isNotEmpty()) channel.trySend(res)
                    } finally {
                        if (completed.incrementAndGet() == totalTasks) channel.close()
                    }
                }
                
                // 5. TCP Nuclear (DNS:53)
                launch(ProxyDispatcher.io) {
                    try {
                        val res = queryTcpDnsNuclear(host, "8.8.4.4", vpnService)
                        if (res.isNotEmpty()) channel.trySend(res)
                    } finally {
                        if (completed.incrementAndGet() == totalTasks) channel.close()
                    }
                }
                
                // 6. DoH Smuggling (HTTPS:443)
                launch(ProxyDispatcher.io) {
                    try {
                        val res = queryDohSmuggling(host, vpnService)
                        if (res.isNotEmpty()) channel.trySend(res)
                    } finally {
                        if (completed.incrementAndGet() == totalTasks) channel.close()
                    }
                }
                
                var result = emptyList<InetAddress>()
                try {
                    result = channel.receive()
                } catch (e: Throwable) { }
                result
            }
        } ?: emptyList()
    }
}

class ProtectedSocketFactory(private val vpnService: VpnService?) : javax.net.SocketFactory() {
    override fun createSocket(): Socket {
        val s = Socket()
        try { vpnService?.protect(s) } catch(e: Throwable) {}
        return s
    }
    override fun createSocket(host: String?, port: Int) = createSocket().apply { connect(InetSocketAddress(host, port)) }
    override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int) = createSocket()
    override fun createSocket(host: InetAddress?, port: Int) = createSocket()
    override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int) = createSocket()
}

class ProtectedSSLSocketFactory(private val base: SSLSocketFactory, private val vpnService: VpnService?) : SSLSocketFactory() {
    override fun getDefaultCipherSuites() = base.defaultCipherSuites
    override fun getSupportedCipherSuites() = base.supportedCipherSuites

    override fun createSocket(s: Socket, host: String, port: Int, autoClose: Boolean): Socket {
        try { vpnService?.protect(s) } catch(e: Throwable) {}
        val sslSocket = base.createSocket(s, host, port, autoClose)
        try { vpnService?.protect(sslSocket) } catch(e: Throwable) {}
        return sslSocket
    }

    override fun createSocket(host: String, port: Int): Socket {
        val s = Socket()
        try { vpnService?.protect(s) } catch(e: Throwable) {}
        s.connect(InetSocketAddress(host, port), 10000)
        return base.createSocket(s, host, port, true)
    }

    override fun createSocket(host: String, port: Int, localHost: java.net.InetAddress, localPort: Int): Socket {
        val s = Socket()
        try { vpnService?.protect(s) } catch(e: Throwable) {}
        s.bind(java.net.InetSocketAddress(localHost, localPort))
        s.connect(InetSocketAddress(host, port), 10000)
        return base.createSocket(s, host, port, true)
    }

    override fun createSocket(host: java.net.InetAddress, port: Int): Socket {
        val s = Socket()
        try { vpnService?.protect(s) } catch(e: Throwable) {}
        s.connect(InetSocketAddress(host, port), 10000)
        return base.createSocket(s, host.hostAddress, port, true)
    }

    override fun createSocket(address: java.net.InetAddress, port: Int, localAddress: java.net.InetAddress, localPort: Int): Socket {
        val s = Socket()
        try { vpnService?.protect(s) } catch(e: Throwable) {}
        s.bind(java.net.InetSocketAddress(localAddress, localPort))
        s.connect(InetSocketAddress(address, port), 10000)
        return base.createSocket(s, address.hostAddress, port, true)
    }
}

class BootstrapDns : Dns {
    override fun lookup(hostname: String): List<InetAddress> {
        // 1. Check Static/Hardcoded IPs for DoH/DoT providers to avoid recursion
        val static = DnsCacheManager.getStaticIps(hostname)
        if (static != null && static.isNotEmpty()) return static

        // 2. Fallback to emergency list for common domains
        val emergency = DnsCacheManager.getEmergencyFallback(hostname)
        if (emergency != null && emergency.isNotEmpty()) return emergency

        // 3. Last resort: standard resolution (might recurse, but we handled the most common ones)
        return try {
            Dns.SYSTEM.lookup(hostname)
        } catch (e: Throwable) {
            emptyList()
        }
    }
}
