package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.net.InetAddress

class DnsCacheManagerTest {

    @Before
    fun setUp() {
        DnsCacheManager.clearAll()
    }

    @Test
    fun testIpAddressDetection() {
        assertTrue(DnsCacheManager.isIpAddress("1.1.1.1"))
        assertTrue(DnsCacheManager.isIpAddress("192.168.1.1"))
        assertTrue(DnsCacheManager.isIpAddress("2001:4860:4860::8888"))
        assertFalse(DnsCacheManager.isIpAddress("google.com"))
        assertFalse(DnsCacheManager.isIpAddress("example.org"))
    }

    @Test
    fun testPoisonedIpFiltering() {
        assertTrue(DnsCacheManager.isPoisoned(InetAddress.getByName("127.0.0.1"), "example.com"))
        assertTrue(DnsCacheManager.isPoisoned(InetAddress.getByName("0.0.0.0"), "example.com"))
        assertTrue(DnsCacheManager.isPoisoned(InetAddress.getByName("10.10.34.34"), "example.com"))
        assertTrue(DnsCacheManager.isPoisoned(InetAddress.getByName("146.112.61.106"), "example.com"))
        assertFalse(DnsCacheManager.isPoisoned(InetAddress.getByName("140.82.112.4"), "github.com"))
        assertFalse(DnsCacheManager.isPoisoned(InetAddress.getByName("8.8.8.8"), "dns.google"))
    }

    @Test
    fun testDnsCachingAndRetrieval() {
        val domain = "example.com"
        val ips = listOf(InetAddress.getByName("93.184.216.34"))
        DnsCacheManager.put(domain, ips, ttlMs = 300000L)

        val cached = DnsCacheManager.getCached(domain)
        assertNotNull(cached)
        assertEquals(1, cached?.size)
        assertEquals("93.184.216.34", cached?.first()?.hostAddress)
    }

    @Test
    fun testEmergencyFallback() {
        val fb = DnsCacheManager.getEmergencyFallback("youtube.com")
        assertNotNull(fb)
        assertTrue(fb!!.isNotEmpty())
    }
}
