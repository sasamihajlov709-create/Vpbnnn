package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
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

    @Test
    fun `test normalizeAndValidateDnsName handles whitespace trailing dots and long names`() {
        assertEquals("google.com", DnsPacketEngine.normalizeAndValidateDnsName("  google.com.  "))
        assertEquals("localhost", DnsPacketEngine.normalizeAndValidateDnsName(""))
        val longLabel = "a".repeat(70)
        val normalized = DnsPacketEngine.normalizeAndValidateDnsName("$longLabel.com")
        assertTrue(normalized.split(".")[0].length <= 63)
    }

    @Test
    fun `test buildQueryContext generates consistent ID and byte payload`() {
        val queryCtx = DnsPacketEngine.buildQueryContext("example.com", 1)
        assertTrue(queryCtx.id in 0..0xFFFF)
        assertEquals("example.com", queryCtx.host)
        assertEquals(1, queryCtx.type)
        assertTrue(queryCtx.rawBytes.isNotEmpty())

        val queryCtxTcp = DnsPacketEngine.buildQueryContextTcp("example.com", 1)
        val tcpLen = ((queryCtxTcp.rawBytes[0].toInt() and 0xFF) shl 8) or (queryCtxTcp.rawBytes[1].toInt() and 0xFF)
        assertEquals(queryCtxTcp.rawBytes.size - 2, tcpLen)
    }

    @Test
    fun `test parseDnsResponse validates expectedId and expectedHost`() {
        val queryCtx = DnsPacketEngine.buildQueryContext("example.com", 1)
        // Construct a mock valid response
        val resp = ByteArray(64)
        // ID matching queryCtx.id
        resp[0] = (queryCtx.id shr 8).toByte()
        resp[1] = (queryCtx.id and 0xFF).toByte()
        resp[2] = 0x81.toByte() // QR=1, RD=1
        resp[3] = 0x80.toByte() // RA=1, RCODE=0
        resp[4] = 0x00 // QDCOUNT=1
        resp[5] = 0x01
        resp[6] = 0x00 // ANCOUNT=1
        resp[7] = 0x01

        // Question: example.com
        var pos = 12
        resp[pos++] = 7
        "example".toByteArray().copyInto(resp, pos)
        pos += 7
        resp[pos++] = 3
        "com".toByteArray().copyInto(resp, pos)
        pos += 3
        resp[pos++] = 0 // End of name
        resp[pos++] = 0 // Type A
        resp[pos++] = 1
        resp[pos++] = 0 // Class IN
        resp[pos++] = 1

        // Answer
        resp[pos++] = 0xC0.toByte() // Pointer
        resp[pos++] = 12.toByte()
        resp[pos++] = 0 // Type A
        resp[pos++] = 1
        resp[pos++] = 0 // Class IN
        resp[pos++] = 1
        resp[pos++] = 0 // TTL
        resp[pos++] = 0
        resp[pos++] = 0
        resp[pos++] = 60
        resp[pos++] = 0 // RDLENGTH = 4
        resp[pos++] = 4
        resp[pos++] = 104.toByte()
        resp[pos++] = 21.toByte()
        resp[pos++] = 55.toByte()
        resp[pos++] = 2.toByte()

        // Valid match
        val res = DnsPacketEngine.parseDnsResponse(resp, pos, expectedId = queryCtx.id, expectedHost = "example.com")
        assertEquals(1, res.size)
        assertEquals("104.21.55.2", res[0].hostAddress)

        // Invalid ID match
        val resBadId = DnsPacketEngine.parseDnsResponse(resp, pos, expectedId = (queryCtx.id + 1) and 0xFFFF, expectedHost = "example.com")
        assertTrue(resBadId.isEmpty())

        // Invalid Host match
        val resBadHost = DnsPacketEngine.parseDnsResponse(resp, pos, expectedId = queryCtx.id, expectedHost = "other.org")
        assertTrue(resBadHost.isEmpty())
    }

    @Test
    fun `test DpiStorage profile isolation does not pollute new profiles`() {
        val app = org.robolectric.RuntimeEnvironment.getApplication()
        DpiEngine.networkStrategyMemory["profile_a"] = java.util.concurrent.ConcurrentHashMap()
        DpiEngine.networkStrategyMemory["profile_a"]!![HostCategory.MESSENGER] = DpiEngine.NetworkMemory(BypassStrategy.SNI_SPLIT, System.currentTimeMillis(), 1.0)

        // Save profile_b which has no network strategy memory
        DpiStorage.saveProfileScores(app, "profile_b", synchronous = true)

        val prefsB = app.getSharedPreferences("dpi_scores_profile_b", android.content.Context.MODE_PRIVATE)
        assertFalse("profile_b should not contain profile_a netmem", prefsB.contains("netmem_profile_a::MESSENGER"))
    }

    @Test
    fun `test ProxyDispatcher executes background jobs safely`() = kotlinx.coroutines.test.runTest {
        val completed = java.util.concurrent.atomic.AtomicBoolean(false)
        val job = kotlinx.coroutines.withContext(ProxyDispatcher.io) {
            completed.set(true)
            true
        }
        assertTrue(job)
        assertTrue(completed.get())
    }

    @Test
    fun `test ObservationQuality weights and memory gating`() {
        val testHost = "unverified-probe.example.com"
        val testStrat = BypassStrategy.TCP_SEGMENT_OVERLAP
        DpiEngine.hostSpecificMemory.remove(testHost)
        DpiEngine.weightedSuccessHistory.remove(testStrat)

        // Weak connection observation should NOT lock in host memory
        DpiStrategySelector.recordResult(
            strategy = testStrat,
            success = true,
            category = HostCategory.OTHER,
            host = testHost,
            quality = ObservationQuality.CONNECT_ONLY
        )
        assertNull("Weak connect-only observation should not persist in host memory", DpiEngine.hostSpecificMemory[testHost])
        val initialWeight = DpiEngine.weightedSuccessHistory[testStrat]?.get() ?: 0L
        assertTrue("Weighted success must be registered", initialWeight > 0)

        // Full data transfer observation SHOULD lock in host memory
        DpiStrategySelector.recordResult(
            strategy = testStrat,
            success = true,
            category = HostCategory.OTHER,
            host = testHost,
            quality = ObservationQuality.FULL_DATA_TRANSFER
        )
        assertNotNull("Full data transfer observation must persist in host memory", DpiEngine.hostSpecificMemory[testHost])
        assertEquals(testStrat, DpiEngine.hostSpecificMemory[testHost]?.strategy)
    }
}

