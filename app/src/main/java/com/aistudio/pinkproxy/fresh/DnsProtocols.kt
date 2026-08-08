package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import java.net.InetAddress
import javax.net.ssl.SSLContext
import okhttp3.*
import java.util.concurrent.TimeUnit

interface DnsResolverEngine {
    suspend fun queryDohRacing(host: String, vpnService: VpnService?, type: Int = 1): List<InetAddress>
    suspend fun queryUdpDnsShadow(host: String, dnsIp: String, vpnService: VpnService?, type: Int = 1): List<InetAddress>
    suspend fun queryDot(host: String, dotIp: String, vpnService: VpnService?, type: Int = 1): List<InetAddress>
    suspend fun queryTcpDnsShadow(host: String, dnsIp: String, vpnService: VpnService?, type: Int = 1): List<InetAddress>
    suspend fun queryDnsOverQuic(host: String, dnsIp: String, vpnService: VpnService?, type: Int = 1): List<InetAddress>
    suspend fun queryHttpsRecord(host: String, vpnService: VpnService?): List<DnsPacketEngine.DnsRecord>
}

class DefaultDnsResolverEngine : DnsResolverEngine {
    override suspend fun queryDohRacing(host: String, vpnService: VpnService?, type: Int): List<InetAddress> = DohDnsProtocols.queryDohRacing(host, vpnService, type)
    override suspend fun queryUdpDnsShadow(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = UdpDnsProtocols.queryUdpDnsShadow(host, dnsIp, vpnService, type)
    override suspend fun queryDot(host: String, dotIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = DotDnsProtocols.queryDot(host, dotIp, vpnService, type)
    override suspend fun queryTcpDnsShadow(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = TcpDnsProtocols.queryTcpDnsShadow(host, dnsIp, vpnService, type)
    override suspend fun queryDnsOverQuic(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = UdpDnsProtocols.queryDnsOverQuic(host, dnsIp, vpnService, type)
    override suspend fun queryHttpsRecord(host: String, vpnService: VpnService?): List<DnsPacketEngine.DnsRecord> = DohDnsProtocols.queryHttpsRecord(host, vpnService)
}

object DnsProtocols {
    @Volatile var engine: DnsResolverEngine = DefaultDnsResolverEngine()

    private val baseOkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .writeTimeout(5, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .connectionPool(ConnectionPool(64, 5, TimeUnit.MINUTES))
            .build()
    }

    private var cachedProtectedClient: OkHttpClient? = null
    private var lastVpnService: VpnService? = null
    private val clientLock = Any()

    fun getProtectedClient(vpnService: VpnService?): OkHttpClient {
        val cached = cachedProtectedClient
        if (cached != null && lastVpnService == vpnService) {
            return cached
        }
        
        return synchronized(clientLock) {
            val existing = cachedProtectedClient
            if (existing != null && lastVpnService == vpnService) {
                existing
            } else {
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
                } catch (e: java.security.GeneralSecurityException) {
                    Log.e("DnsProtocols", "Security exception setting up protected SSL", e)
                } catch (e: Exception) {
                    Log.e("DnsProtocols", "Unexpected error setting up protected SSL", e)
                }
                
                val client = builder.build()
                cachedProtectedClient = client
                lastVpnService = vpnService
                client
            }
        }
    }

    suspend fun queryDnsOverQuic(host: String, dnsIp: String, vpnService: VpnService?, type: Int = 1): List<InetAddress> =
        engine.queryDnsOverQuic(host, dnsIp, vpnService, type)

    suspend fun queryUdpDnsDetailed(host: String, dnsIp: String, vpnService: VpnService?, type: Int = 1): List<DnsPacketEngine.DnsRecord> =
        UdpDnsProtocols.queryUdpDnsDetailed(host, dnsIp, vpnService, type)

    suspend fun queryUdpDnsReorder(host: String, dnsIp: String, vpnService: VpnService?, type: Int = 1): List<InetAddress> =
        UdpDnsProtocols.queryUdpDnsReorder(host, dnsIp, vpnService, type)

    suspend fun queryUdpDns(host: String, dnsIp: String, vpnService: VpnService?, type: Int = 1): List<InetAddress> =
        UdpDnsProtocols.queryUdpDns(host, dnsIp, vpnService, type)

    suspend fun queryUdpDnsNuclear(host: String, dnsIp: String, vpnService: VpnService?, type: Int = 1): List<InetAddress> =
        UdpDnsProtocols.queryUdpDnsNuclear(host, dnsIp, vpnService, type)

    suspend fun queryUdpDnsShadow(host: String, dnsIp: String, vpnService: VpnService?, type: Int = 1): List<InetAddress> =
        engine.queryUdpDnsShadow(host, dnsIp, vpnService, type)

    suspend fun queryTcpDnsShadow(host: String, dnsIp: String, vpnService: VpnService?, type: Int = 1): List<InetAddress> =
        engine.queryTcpDnsShadow(host, dnsIp, vpnService, type)

    suspend fun queryTcpDnsNuclear(host: String, dnsIp: String, vpnService: VpnService?, type: Int = 1): List<InetAddress> =
        TcpDnsProtocols.queryTcpDnsNuclear(host, dnsIp, vpnService, type)

    suspend fun queryTcpDns(host: String, dnsIp: String, vpnService: VpnService?, type: Int = 1): List<InetAddress> =
        TcpDnsProtocols.queryTcpDns(host, dnsIp, vpnService, type)

    suspend fun queryDnsOverTcp(host: String, dnsIp: String, vpnService: VpnService?, type: Int = 1): List<InetAddress> =
        TcpDnsProtocols.queryDnsOverTcp(host, dnsIp, vpnService, type)

    suspend fun queryDohDetailed(host: String, dohUrl: String, vpnService: VpnService?, type: Int = 1): List<DnsPacketEngine.DnsRecord> =
        DohDnsProtocols.queryDohDetailed(host, dohUrl, vpnService, type)

    suspend fun queryDoh(host: String, dohUrl: String, vpnService: VpnService?, type: Int = 1): List<InetAddress> =
        DohDnsProtocols.queryDoh(host, dohUrl, vpnService, type)

    suspend fun queryHttpsRecord(host: String, vpnService: VpnService?): List<DnsPacketEngine.DnsRecord> =
        engine.queryHttpsRecord(host, vpnService)

    suspend fun queryDohJson(host: String, vpnService: VpnService?, type: Int = 1): List<InetAddress> =
        DohDnsProtocols.queryDohJson(host, vpnService, type)

    suspend fun queryDohRacing(host: String, vpnService: VpnService?, type: Int = 1): List<InetAddress> =
        engine.queryDohRacing(host, vpnService, type)

    suspend fun queryDohExtreme(host: String, vpnService: VpnService?, type: Int = 1): List<InetAddress> =
        DohDnsProtocols.queryDohExtreme(host, vpnService, type)

    suspend fun queryDohSmuggling(host: String, vpnService: VpnService?, type: Int = 1): List<InetAddress> =
        DohDnsProtocols.queryDohSmuggling(host, vpnService, type)

    fun clearPool() {
        DotDnsProtocols.clearPool()
        DnsCacheManager.clearAll()
    }

    suspend fun queryDot(host: String, dotIp: String, vpnService: VpnService?, type: Int = 1): List<InetAddress> =
        engine.queryDot(host, dotIp, vpnService, type)

    suspend fun queryDnsExtremeRacing(host: String, vpnService: VpnService?, type: Int = 1): List<InetAddress> {
        // High concurrency DNS strategy delegated to DoH racing
        return engine.queryDohRacing(host, vpnService, type)
    }
}
