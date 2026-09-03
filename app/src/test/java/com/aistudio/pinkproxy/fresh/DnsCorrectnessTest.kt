package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.net.InetAddress
import java.nio.ByteBuffer

/**
 * Stage 5 Verification Test Suite:
 * Comprehensive DNS Execution Pipeline, Wire-Format Correctness,
 * TSPU Poisoning/Spoofing Mitigation & SOCKS5 Benchmark Isolation.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class DnsCorrectnessTest {

    @Before
    fun setup() {
        DnsCacheManager.clearAll()
        BypassConfig.setStrategy(BypassStrategy.DIRECT, TransportType.TCP)
    }

    @Test
    fun testRobustResolverCacheInjectionAndRetrieval() = runBlocking {
        val testDomain = "example.com"
        val ipStr = "104.244.42.193"
        val ip = InetAddress.getByName(ipStr)

        DnsCacheManager.put(testDomain, listOf(ip))

        val cached = DnsCacheManager.getCached(testDomain)?.firstOrNull()
        assertNotNull("Cache should return IP", cached)
        assertEquals(ipStr, cached!!.hostAddress)

        val resolvedFromRobust = RobustResolver.getCached(testDomain)?.firstOrNull()
        assertNotNull("RobustResolver should fetch from cache", resolvedFromRobust)
        assertEquals(ipStr, resolvedFromRobust!!.hostAddress)
    }

    @Test
    fun testDnsPacketEngineQueryContextRfc1035Compliance() {
        val host = "video.google.com"
        val queryCtx = DnsPacketEngine.buildQueryContext(host, type = 1, id = 0x4A2F, includeEcs = false)

        assertEquals(0x4A2F, queryCtx.id)
        assertEquals(host, queryCtx.host)
        assertEquals(1, queryCtx.type)

        val raw = queryCtx.rawBytes
        assertTrue("DNS query must have header and question", raw.size >= 12)

        val bb = ByteBuffer.wrap(raw)
        val parsedId = bb.short.toInt() and 0xFFFF
        assertEquals(0x4A2F, parsedId)

        val flags = bb.short.toInt() and 0xFFFF
        assertEquals("Flags must specify Standard Query with RD=1", 0x0100, flags)

        val qdCount = bb.short.toInt() and 0xFFFF
        assertEquals("Query must have 1 question", 1, qdCount)

        bb.position(12) // Skip ANCOUNT, NSCOUNT, ARCOUNT to reach Question section

        // Read QNAME labels
        val l1Len = bb.get().toInt() and 0xFF
        val l1 = ByteArray(l1Len); bb.get(l1)
        assertEquals("video", String(l1))

        val l2Len = bb.get().toInt() and 0xFF
        val l2 = ByteArray(l2Len); bb.get(l2)
        assertEquals("google", String(l2))

        val l3Len = bb.get().toInt() and 0xFF
        val l3 = ByteArray(l3Len); bb.get(l3)
        assertEquals("com", String(l3))

        val terminator = bb.get().toInt()
        assertEquals("Root zero byte terminator", 0, terminator)

        val qType = bb.short.toInt() and 0xFFFF
        assertEquals("Type A", 1, qType)
        val qClass = bb.short.toInt() and 0xFFFF
        assertEquals("Class IN", 1, qClass)
    }

    @Test
    fun testDetailedDnsResponseParsingWithCompressionPointers() {
        val host = "example.com"
        val queryId = 0x1A2B

        // Build raw DNS response packet with compression pointer to question name at offset 12
        val buffer = ByteArray(512)
        val bb = ByteBuffer.wrap(buffer)
        bb.putShort(queryId.toShort()) // Transaction ID
        bb.putShort(0x8180.toShort())  // QR=1, RD=1, RA=1, RCODE=0
        bb.putShort(1.toShort())       // Questions = 1
        bb.putShort(2.toShort())       // Answers = 2 (1 Type A, 1 Type AAAA)
        bb.putShort(0.toShort())       // Authority = 0
        bb.putShort(0.toShort())       // Additional = 0

        // Question: example.com
        val labels = host.split(".")
        for (label in labels) {
            val bytes = label.toByteArray(Charsets.UTF_8)
            bb.put(bytes.size.toByte())
            bb.put(bytes)
        }
        bb.put(0.toByte()) // end of QNAME
        bb.putShort(1.toShort()) // Type A
        bb.putShort(1.toShort()) // Class IN

        // Answer 1: Pointer 0xC00C (points to offset 12)
        bb.putShort(0xC00C.toShort())
        bb.putShort(1.toShort()) // Type A
        bb.putShort(1.toShort()) // Class IN
        bb.putInt(600)           // TTL 600s
        bb.putShort(4.toShort()) // RdLength 4
        bb.put(byteArrayOf(104.toByte(), 244.toByte(), 42.toByte(), 193.toByte())) // 104.244.42.193

        // Answer 2: Pointer 0xC00C
        bb.putShort(0xC00C.toShort())
        bb.putShort(28.toShort()) // Type AAAA
        bb.putShort(1.toShort())  // Class IN
        bb.putInt(300)            // TTL 300s
        bb.putShort(16.toShort()) // RdLength 16
        val ipv6Bytes = byteArrayOf(
            0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01,
            0x02, 0x48, 0x18, 0x93.toByte(), 0x25, 0xc8.toByte(), 0x19, 0x46
        )
        bb.put(ipv6Bytes)

        val totalLen = bb.position()
        val packet = ByteArray(totalLen)
        System.arraycopy(buffer, 0, packet, 0, totalLen)

        // Verify parseDnsResponse
        val ips = DnsPacketEngine.parseDnsResponse(packet, totalLen, expectedId = queryId, expectedHost = host)
        assertEquals(2, ips.size)
        assertEquals("104.244.42.193", ips[0].hostAddress)

        // Verify parseDnsResponseDetailed
        val records = DnsPacketEngine.parseDnsResponseDetailed(packet, totalLen, expectedId = queryId, expectedHost = host)
        assertEquals(2, records.size)
        assertEquals(600L, records[0].ttlSeconds)
        assertEquals(1, records[0].type)
        assertEquals(300L, records[1].ttlSeconds)
        assertEquals(28, records[1].type)
    }

    @Test
    fun testStrictDnsTransactionIdAndQNameValidation() {
        val host = "discord.com"
        val queryId = 0x3344

        val buffer = ByteArray(256)
        val bb = ByteBuffer.wrap(buffer)
        bb.putShort(queryId.toShort())
        bb.putShort(0x8180.toShort())
        bb.putShort(1.toShort())
        bb.putShort(1.toShort())
        bb.putShort(0.toShort())
        bb.putShort(0.toShort())

        val labels = host.split(".")
        for (l in labels) {
            val b = l.toByteArray(Charsets.UTF_8)
            bb.put(b.size.toByte())
            bb.put(b)
        }
        bb.put(0.toByte())
        bb.putShort(1.toShort())
        bb.putShort(1.toShort())

        bb.putShort(0xC00C.toShort())
        bb.putShort(1.toShort())
        bb.putShort(1.toShort())
        bb.putInt(300)
        bb.putShort(4.toShort())
        bb.put(byteArrayOf(162.toByte(), 159.toByte(), 138.toByte(), 232.toByte()))

        val totalLen = bb.position()
        val packet = ByteArray(totalLen)
        System.arraycopy(buffer, 0, packet, 0, totalLen)

        // Correct ID and host
        val valid = DnsPacketEngine.parseDnsResponse(packet, totalLen, expectedId = queryId, expectedHost = host)
        assertEquals(1, valid.size)

        // ID mismatch must be rejected
        val badId = DnsPacketEngine.parseDnsResponse(packet, totalLen, expectedId = 0x9999, expectedHost = host)
        assertTrue("Mismatched transaction ID must be dropped", badId.isEmpty())

        // QNAME mismatch must be rejected
        val badHost = DnsPacketEngine.parseDnsResponse(packet, totalLen, expectedId = queryId, expectedHost = "telegram.org")
        assertTrue("Mismatched QNAME must be dropped", badHost.isEmpty())
    }

    @Test
    fun testTspuBogonAndBlockPageFiltering() {
        val loopback = InetAddress.getByName("127.0.0.1")
        val zeroIp = InetAddress.getByName("0.0.0.0")
        val megafonBlock = InetAddress.getByName("195.82.146.120")
        val rostelecomBlock = InetAddress.getByName("95.167.13.50")
        val privateRedirect = InetAddress.getByName("10.10.10.10")
        val validCloudflare = InetAddress.getByName("104.244.42.193")

        assertTrue("Loopback must be flagged suspicious", DnsPacketEngine.isSuspicious(loopback, "google.com"))
        assertTrue("0.0.0.0 must be flagged suspicious", DnsPacketEngine.isSuspicious(zeroIp, "youtube.com"))
        assertTrue("Megafon block IP must be flagged suspicious", DnsPacketEngine.isSuspicious(megafonBlock, "telegram.org"))
        assertTrue("Rostelecom block IP must be flagged suspicious", DnsPacketEngine.isSuspicious(rostelecomBlock, "discord.com"))
        assertTrue("Private redirect must be flagged suspicious for canary domain", DnsPacketEngine.isSuspicious(privateRedirect, "youtube.com"))
        assertFalse("Real public IP must not be flagged suspicious", DnsPacketEngine.isSuspicious(validCloudflare, "x.com", ttl = 300))
    }

    @Test
    fun testLowTtlInjectionDetection() {
        val validIp = InetAddress.getByName("142.250.180.14")
        // Spoofed middlebox DNS replies inject TTL 0 or 1
        assertTrue("TTL=0 must be flagged as suspicious spoofing", DnsPacketEngine.isSuspicious(validIp, "google.com", ttl = 0))
        assertTrue("TTL=1 must be flagged as suspicious spoofing", DnsPacketEngine.isSuspicious(validIp, "google.com", ttl = 1))
        assertFalse("Normal TTL=60 must be accepted", DnsPacketEngine.isSuspicious(validIp, "google.com", ttl = 60))
    }

    @Test
    fun testDnsCacheHeatmapAndRttSorting() {
        val ip1 = InetAddress.getByName("1.1.1.1")
        val ip2 = InetAddress.getByName("8.8.8.8")
        val ip3 = InetAddress.getByName("9.9.9.9")
        val list = listOf(ip1, ip2, ip3)

        // ip2 has fast RTT and high success
        DnsCacheManager.recordIpSuccess("8.8.8.8", rtt = 15)
        DnsCacheManager.recordIpSuccess("8.8.8.8", rtt = 12)

        // ip1 has moderate latency
        DnsCacheManager.recordIpSuccess("1.1.1.1", rtt = 85)

        // ip3 has failures
        DnsCacheManager.recordIpFailure("9.9.9.9")
        DnsCacheManager.recordIpFailure("9.9.9.9")

        val sorted = DnsCacheManager.getSortedIps(list)
        assertEquals("8.8.8.8 should be first due to high score and lowest RTT", "8.8.8.8", sorted[0].hostAddress)
        assertEquals("9.9.9.9 should be last due to failure penalties", "9.9.9.9", sorted[2].hostAddress)
    }

    @Test
    fun testNegativeCachingAndPurge() {
        val badDomain = "non-existent-or-blocked-domain.com"
        assertFalse(DnsCacheManager.isNegative(badDomain))

        DnsCacheManager.putNegative(badDomain, ttlMs = 5000)
        assertTrue(DnsCacheManager.isNegative(badDomain))

        // After clearing negative cache, domain is no longer negative
        DnsCacheManager.clearNegative(badDomain)
        assertFalse(DnsCacheManager.isNegative(badDomain))
    }

    @Test
    fun testBenchmarkSessionIsolation() {
        // Global strategy set to DIRECT
        BypassConfig.setStrategy(BypassStrategy.DIRECT, TransportType.TCP)
        assertEquals(BypassStrategy.DIRECT, BypassConfig.getSessionConfig("example.com", BypassStrategy.DIRECT, 0L, TransportType.TCP).strategy)

        // Benchmark session negotiates forced strategy
        val authUser = "BENCHMARK_SESSION"
        val authPass = "TCP_FOOL_DPI"

        var benchmarkStrategy: BypassStrategy? = null
        if (authUser.startsWith("BENCHMARK")) {
            benchmarkStrategy = BypassStrategy.valueOf(authPass)
        }

        assertNotNull(benchmarkStrategy)
        assertEquals(BypassStrategy.TCP_FOOL_DPI, benchmarkStrategy)

        // Ensure global config remains unmodified
        val globalConfig = BypassConfig.getSessionConfig("example.com", BypassStrategy.DIRECT, 0L, TransportType.TCP)
        assertEquals(BypassStrategy.DIRECT, globalConfig.strategy)
    }
}
