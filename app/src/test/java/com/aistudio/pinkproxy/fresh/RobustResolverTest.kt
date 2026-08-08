package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.net.InetAddress

class FakeDnsResolverEngine : DnsResolverEngine {
    var dohRacingHandler: ((String, Int) -> List<InetAddress>)? = null
    var dohRacingCalls = 0

    override suspend fun queryDohRacing(host: String, vpnService: android.net.VpnService?, type: Int): List<InetAddress> {
        dohRacingCalls++
        return dohRacingHandler?.invoke(host, type) ?: emptyList()
    }

    override suspend fun queryUdpDnsShadow(host: String, dnsIp: String, vpnService: android.net.VpnService?, type: Int): List<InetAddress> = emptyList()
    override suspend fun queryDot(host: String, dotIp: String, vpnService: android.net.VpnService?, type: Int): List<InetAddress> = emptyList()
    override suspend fun queryTcpDnsShadow(host: String, dnsIp: String, vpnService: android.net.VpnService?, type: Int): List<InetAddress> = emptyList()
    override suspend fun queryDnsOverQuic(host: String, dnsIp: String, vpnService: android.net.VpnService?, type: Int): List<InetAddress> = emptyList()
    override suspend fun queryHttpsRecord(host: String, vpnService: android.net.VpnService?): List<DnsPacketEngine.DnsRecord> = emptyList()
}

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class RobustResolverTest {

    private val ipv4Addr by lazy { InetAddress.getByName("104.16.123.96") }
    private val ipv6Addr by lazy { InetAddress.getByName("2606:4700:4700::1111") }
    private lateinit var fakeEngine: FakeDnsResolverEngine

    @Before
    fun setUp() {
        ProxyDispatcher.context = org.robolectric.RuntimeEnvironment.getApplication()
        fakeEngine = FakeDnsResolverEngine()
        DnsProtocols.engine = fakeEngine
        RobustResolver.initialize(kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Unconfined))
        
        // Setup default behavior
        BypassConfig.includeIpv6 = false
        BypassConfig.preferIpv6 = false
        
        RobustResolver.clearCache()
    }

    @After
    fun tearDown() {
        DnsProtocols.engine = DefaultDnsResolverEngine()
    }

    @Test
    fun `resolve returns cached value if available`() = runTest {
        val host = "google.com"
        val expected = listOf(ipv4Addr)
        
        DnsCacheManager.put(host, expected, type = 1)

        val result = RobustResolver.resolve(host)
        
        assertEquals(expected, result)
        // Verify no network call was made
        assertEquals(0, fakeEngine.dohRacingCalls)
    }

    @Test
    fun `resolve performs parallel resolution on cache miss`() = runTest {
        val host = "example.com"
        val expected = listOf(ipv4Addr)
        
        DnsCacheManager.clearAll()
        fakeEngine.dohRacingHandler = { h, type -> if (h == host && type == 1) expected else emptyList() }

        val result = RobustResolver.resolve(host)
        
        assertEquals(expected, result)
        assertTrue(fakeEngine.dohRacingCalls > 0)
    }

    @Test
    fun `resolveDual handles IPv6 when enabled`() = runTest {
        val host = "ipv6.example.com"
        val aResult = listOf(ipv4Addr)
        val aaaaResult = listOf(ipv6Addr)
        
        BypassConfig.includeIpv6 = true
        DnsCacheManager.clearAll()
        
        fakeEngine.dohRacingHandler = { h, type ->
            if (h.contains(host)) {
                if (type == 28) aaaaResult else aResult
            } else emptyList()
        }

        val result = RobustResolver.resolveDual(host)
        
        assertTrue(result.contains(ipv4Addr))
        assertTrue(result.contains(ipv6Addr))
        assertEquals(2, result.size)
    }

    @Test
    fun `resolveDual returns only IPv4 when IPv6 is disabled`() = runTest {
        val host = "dual.example.com"
        BypassConfig.includeIpv6 = false
        DnsCacheManager.clearAll()
        
        fakeEngine.dohRacingHandler = { h, type ->
            if (h == host && type == 1) listOf(ipv4Addr)
            else emptyList()
        }

        val result = RobustResolver.resolveDual(host)
        
        assertEquals(listOf(ipv4Addr), result)
    }
}

