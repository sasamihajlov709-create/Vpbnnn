package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.net.InetAddress
import java.nio.ByteBuffer

class DnsPacketEngineAndPoisoningTest {

    @Before
    fun setup() {
        DnsCacheManager.clearAll()
    }

    @Test
    fun testBuildDnsQueryStructure() {
        val query = DnsPacketEngine.buildDnsQuery("example.com", 1, id = 0x1234, mangleCase = false)
        assertTrue(query.size > 12)
        val bb = ByteBuffer.wrap(query)
        val id = bb.short.toInt() and 0xFFFF
        assertEquals(0x1234, id)
        val flags = bb.short.toInt() and 0xFFFF
        assertEquals(0x0100, flags) // Standard query with RD=1
    }

    @Test
    fun testDetectKnownPoisonedAndBogonIps() {
        val loopback = InetAddress.getByName("127.0.0.1")
        val zeroIp = InetAddress.getByName("0.0.0.0")
        val megafonBlock = InetAddress.getByName("195.82.146.120")
        val rostelecomBlock = InetAddress.getByName("95.167.13.50")
        val validGoogle = InetAddress.getByName("142.250.180.14")

        assertTrue("127.0.0.1 must be marked suspicious", DnsPacketEngine.isSuspicious(loopback, "google.com"))
        assertTrue("0.0.0.0 must be marked suspicious", DnsPacketEngine.isSuspicious(zeroIp, "youtube.com"))
        assertTrue("195.82.146.120 must be marked suspicious", DnsPacketEngine.isSuspicious(megafonBlock, "telegram.org"))
        assertTrue("95.167.13.50 must be marked suspicious", DnsPacketEngine.isSuspicious(rostelecomBlock, "discord.com"))
        assertFalse("Real Google IP must be clean", DnsPacketEngine.isSuspicious(validGoogle, "google.com", ttl = 300))
    }

    @Test
    fun testLowTtlSpoofingDetection() {
        val validIp = InetAddress.getByName("1.2.3.5")
        // TTL <= 1 is a known TSPU DNS injection indicator
        assertTrue("TTL <= 1 must be flagged as suspicious", DnsPacketEngine.isSuspicious(validIp, "youtube.com", ttl = 0))
        assertTrue("TTL == 1 must be flagged as suspicious", DnsPacketEngine.isSuspicious(validIp, "youtube.com", ttl = 1))
        assertFalse("TTL > 1 should not trigger TTL-based suspicion", DnsPacketEngine.isSuspicious(validIp, "example.com", ttl = 60))
    }

    @Test
    fun testDnsCacheManagerSortingAndHeatmap() {
        val ip1 = InetAddress.getByName("1.1.1.1")
        val ip2 = InetAddress.getByName("8.8.8.8")
        val list = listOf(ip1, ip2)

        DnsCacheManager.recordIpSuccess("8.8.8.8", rtt = 20)
        DnsCacheManager.recordIpFailure("1.1.1.1")

        val sorted = DnsCacheManager.getSortedIps(list)
        assertEquals("Higher reputation IP must be sorted first", "8.8.8.8", sorted.first().hostAddress)
    }

    @Test
    fun testDnsEmergencyFallbackLookup() {
        val youtubeFallback = DnsCacheManager.getEmergencyFallback("youtube.com")
        assertNotNull("YouTube must have emergency static fallback", youtubeFallback)
        assertTrue(youtubeFallback!!.isNotEmpty())

        val subYoutubeFallback = DnsCacheManager.getEmergencyFallback("rr1---sn-4g5ednle.googlevideo.com")
        assertNotNull("googlevideo subdomain must match parent fallback", subYoutubeFallback)
        assertTrue(subYoutubeFallback!!.isNotEmpty())
    }
}
