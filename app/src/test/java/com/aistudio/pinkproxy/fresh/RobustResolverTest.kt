package com.aistudio.pinkproxy.fresh

import io.mockk.*
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

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class RobustResolverTest {

    private val ipv4Addr by lazy { InetAddress.getByName("1.2.3.4") }
    private val ipv6Addr by lazy { InetAddress.getByName("2001:db8::1") }

    @Before
    fun setUp() {
        ProxyDispatcher.context = org.robolectric.RuntimeEnvironment.getApplication()
        mockkObject(DnsProtocols)
        mockkObject(BypassConfig)
        
        // Setup default behavior
        every { BypassConfig.includeIpv6 } returns false
        every { BypassConfig.preferIpv6 } returns false
        
        RobustResolver.clearCache()
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `resolve returns cached value if available`() = runTest {
        val host = "google.com"
        val expected = listOf(ipv4Addr)
        
        DnsCacheManager.put(host, expected, type = 1)

        val result = RobustResolver.resolve(host)
        
        assertEquals(expected, result)
        // Verify no network call was made
        coVerify(exactly = 0) { DnsProtocols.queryDohRacing(any(), any(), any()) }
    }

    @Test
    fun `resolve performs parallel resolution on cache miss`() = runTest {
        val host = "example.com"
        val expected = listOf(ipv4Addr)
        
        DnsCacheManager.clearAll()
        
        coEvery { DnsProtocols.queryDohRacing(host, any(), 1) } returns expected
        coEvery { DnsProtocols.queryUdpDnsShadow(host, any(), any(), 1) } returns emptyList()
        coEvery { DnsProtocols.queryDot(host, any(), any(), 1) } returns emptyList()
        coEvery { DnsProtocols.queryTcpDnsShadow(host, any(), any(), 1) } returns emptyList()
        coEvery { DnsProtocols.queryDnsOverQuic(host, any(), any(), 1) } returns emptyList()
        coEvery { DnsProtocols.queryHttpsRecord(host, any()) } returns emptyList()

        val result = RobustResolver.resolve(host)
        
        assertEquals(expected, result)
        coVerify { DnsProtocols.queryDohRacing(host, any(), 1) }
    }

    @Test
    fun `resolveDual handles IPv6 when enabled`() = runTest {
        val host = "ipv6.example.com"
        val aResult = listOf(ipv4Addr)
        val aaaaResult = listOf(ipv6Addr)
        
        every { BypassConfig.includeIpv6 } returns true
        DnsCacheManager.clearAll()
        
        // Mock IPv4 resolution
        coEvery { DnsProtocols.queryDohRacing(host, any(), 1) } returns aResult
        coEvery { DnsProtocols.queryUdpDnsShadow(host, any(), any(), 1) } returns emptyList()
        coEvery { DnsProtocols.queryDot(host, any(), any(), 1) } returns emptyList()
        coEvery { DnsProtocols.queryTcpDnsShadow(host, any(), any(), 1) } returns emptyList()
        coEvery { DnsProtocols.queryDnsOverQuic(host, any(), any(), 1) } returns emptyList()
        
        // Mock IPv6 resolution
        coEvery { DnsProtocols.queryDohRacing(host, any(), 28) } returns aaaaResult
        coEvery { DnsProtocols.queryUdpDnsShadow(host, any(), any(), 28) } returns emptyList()
        coEvery { DnsProtocols.queryDot(host, any(), any(), 28) } returns emptyList()
        coEvery { DnsProtocols.queryTcpDnsShadow(host, any(), any(), 28) } returns emptyList()
        coEvery { DnsProtocols.queryDnsOverQuic(host, any(), any(), 28) } returns emptyList()
        coEvery { DnsProtocols.queryHttpsRecord(host, any()) } returns emptyList()

        val result = RobustResolver.resolveDual(host)
        
        assertTrue(result.contains(ipv4Addr))
        assertTrue(result.contains(ipv6Addr))
        assertEquals(2, result.size)
    }

    @Test
    fun `resolveDual returns only IPv4 when IPv6 is disabled`() = runTest {
        val host = "dual.example.com"
        every { BypassConfig.includeIpv6 } returns false
        DnsCacheManager.clearAll()
        
        coEvery { DnsProtocols.queryDohRacing(host, any(), 1) } returns listOf(ipv4Addr)
        coEvery { DnsProtocols.queryUdpDnsShadow(host, any(), any(), 1) } returns emptyList()
        coEvery { DnsProtocols.queryDot(host, any(), any(), 1) } returns emptyList()
        coEvery { DnsProtocols.queryTcpDnsShadow(host, any(), any(), 1) } returns emptyList()
        coEvery { DnsProtocols.queryDnsOverQuic(host, any(), any(), 1) } returns emptyList()
        coEvery { DnsProtocols.queryHttpsRecord(host, any()) } returns emptyList()

        val result = RobustResolver.resolveDual(host)
        
        assertEquals(listOf(ipv4Addr), result)
        coVerify(exactly = 0) { DnsProtocols.queryDohRacing(any(), any(), 28) }
    }
}
