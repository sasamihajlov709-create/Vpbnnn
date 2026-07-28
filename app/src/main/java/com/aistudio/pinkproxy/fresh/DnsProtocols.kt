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
        if (cachedProtectedClient != null && lastVpnService == vpnService) {
            return cachedProtectedClient!!
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
        } finally {
            ProxyStats.release8k(buffer)
            try { socket.close() } catch (e: Throwable) {}
        }
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
            
            // 2. Fragmented Real Query
            if (queryReal.size > 10 && ProxyStats.censorshipIntensity.value > 40) {
                val split = rnd.nextInt(2, queryReal.size - 2)
                val p1 = queryReal.copyOfRange(0, split)
                val p2 = queryReal.copyOfRange(split, queryReal.size)
                
                // This is a trick: some middleboxes reassemble UDP fragments if they have the same ID? 
                // No, standard UDP has no reassembly. But we send them as separate packets.
                // Middleboxes that only look at the first packet will miss the query.
                socket.send(DatagramPacket(p1, p1.size))
                delay(rnd.nextLong(1, 3))
                socket.send(DatagramPacket(p2, p2.size))
                
                // Also send a "Noise" packet between them or after
                val noise = FakePacketHelper.buildUdpNoise(rnd.nextInt(16, 64))
                TtlHelper.setUdpTtl(socket, 1, isIpv6) // Extremely low TTL
                socket.send(DatagramPacket(noise, noise.size))
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
            } else {
                socket.send(DatagramPacket(queryReal, queryReal.size))
            }
            
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

    suspend fun queryDot(host: String, dotIp: String, vpnService: VpnService?): List<InetAddress> {
        val id = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
        val query = DnsPacketEngine.buildDnsQuery(host, 1, id)
        
        val trustManagerFactory = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm())
        trustManagerFactory.init(null as java.security.KeyStore?)
        val trustManagers = trustManagerFactory.trustManagers
        val defaultTrustManager = trustManagers.firstOrNull { it is javax.net.ssl.X509TrustManager } as? javax.net.ssl.X509TrustManager
        
        val sc = SSLContext.getInstance("TLS")
        sc.init(null, if (defaultTrustManager != null) arrayOf(defaultTrustManager) else null, null)
        
        val factory = ProtectedSSLSocketFactory(sc.socketFactory, vpnService)
        val sslSocket = factory.createSocket() as? javax.net.ssl.SSLSocket ?: return emptyList()
        
        try {
            sslSocket.connect(InetSocketAddress(dotIp, 853), 3000)
            sslSocket.soTimeout = 3000
            sslSocket.startHandshake()

            val session = sslSocket.session
            val verifier = HttpsURLConnection.getDefaultHostnameVerifier()
            val expectedHost = dotHostnames[dotIp] ?: dotIp
            
            if (!verifier.verify(expectedHost, session)) {
                Log.w("DnsProtocols", "DoT hostname verification failed for $dotIp (expected $expectedHost)")
                return emptyList()
            }

            val dos = DataOutputStream(sslSocket.getOutputStream())
            dos.writeShort(query.size)
            dos.write(query)
            dos.flush()
            
            val dis = DataInputStream(sslSocket.getInputStream())
            val len = dis.readUnsignedShort()
            if (len > 8192) return emptyList()
            val resp = ByteArray(len)
            dis.readFully(resp)
            val ips = DnsPacketEngine.parseDnsResponse(resp, len, id)
            return ips.filter { !DnsCacheManager.isPoisoned(it, host) }
        } catch (e: Throwable) {
        } finally {
            try { sslSocket.close() } catch (e: Throwable) {}
        }
        return emptyList()
    }

    suspend fun queryDnsOverTcp(host: String, dnsIp: String, vpnService: VpnService?): List<InetAddress> {
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

    suspend fun queryDoh(host: String, dohUrl: String, vpnService: VpnService?): List<InetAddress> {
        val intensity = ProxyStats.censorshipIntensity.value
        val timeout = (if (intensity > 80) 6000L else 4000L) + java.util.concurrent.ThreadLocalRandom.current().nextLong(0, 500)
        
        val query = DnsPacketEngine.buildDnsQuery(host, 1)
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
                    val paddingSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(32, 128)
                    header("X-Dns-Padding", ByteArray(paddingSize) { 'X'.code.toByte() }.toString(Charsets.US_ASCII))
                    if (intensity > 60) {
                        header("X-Forwarded-For", "${java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 255)}.0.0.1")
                        header("Cache-Control", "no-cache")
                    }
                }
                .build()

            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val body = response.body?.bytes() ?: return emptyList()
                    val ips = DnsPacketEngine.parseDnsResponse(body, body.size)
                    val filtered = ips.filter { !DnsCacheManager.isPoisoned(it, host) }
                    if (filtered.isNotEmpty()) return filtered
                }
            }
        } catch (e: Throwable) {
        }
        return emptyList()
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
                            // Staggered racing: give top 2 providers a head start
                            if (index >= 2) delay(120L * (index - 1))
                            val res = queryDoh(host, url, vpnService)
                            if (res.isNotEmpty()) {
                                channel.trySend(res)
                                DnsOptimizer.recordDohSuccess(url)
                            } else {
                                DnsOptimizer.recordDohFailure(url)
                            }
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
        val s = base.createSocket(host, port)
        try { vpnService?.protect(s) } catch(e: Throwable) {}
        return s
    }

    override fun createSocket(host: String, port: Int, localHost: java.net.InetAddress, localPort: Int): Socket {
        val s = base.createSocket(host, port, localHost, localPort)
        try { vpnService?.protect(s) } catch(e: Throwable) {}
        return s
    }

    override fun createSocket(host: java.net.InetAddress, port: Int): Socket {
        val s = base.createSocket(host, port)
        try { vpnService?.protect(s) } catch(e: Throwable) {}
        return s
    }

    override fun createSocket(address: java.net.InetAddress, port: Int, localAddress: java.net.InetAddress, localPort: Int): Socket {
        val s = base.createSocket(address, port, localAddress, localPort)
        try { vpnService?.protect(s) } catch(e: Throwable) {}
        return s
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
