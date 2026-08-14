package com.aistudio.pinkproxy.fresh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.net.InetAddress
import java.nio.ByteBuffer

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class DnsPipelineVerificationTest {

    @Test
    fun testBuildDnsQueryWithoutEcsByDefault() {
        val query = DnsPacketEngine.buildDnsQuery("example.com", 1, id = 0x1234, includeEcs = false)
        assertTrue("Query must be at least 12 bytes", query.size >= 12)
        val id = ((query[0].toInt() and 0xFF) shl 8) or (query[1].toInt() and 0xFF)
        assertEquals(0x1234, id)
    }

    @Test
    fun testParseDnsResponseValidatesExpectedId() {
        val host = "example.com"
        val queryId = 0x5678
        
        // Build raw DNS response from scratch: ID, Flags (0x8180 Standard response NoError), QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
        val buffer = ByteArray(512)
        val bb = ByteBuffer.wrap(buffer)
        bb.putShort(queryId.toShort()) // ID
        bb.putShort(0x8180.toShort())  // Flags: QR=1, RD=1, RA=1, RCODE=0
        bb.putShort(1.toShort())       // Questions = 1
        bb.putShort(1.toShort())       // Answer RRs = 1
        bb.putShort(0.toShort())       // Authority = 0
        bb.putShort(0.toShort())       // Additional = 0

        // Question: example.com, Type A, Class IN
        val labels = host.split(".")
        for (l in labels) {
            val b = l.toByteArray(Charsets.UTF_8)
            bb.put(b.size.toByte())
            bb.put(b)
        }
        bb.put(0.toByte())
        bb.putShort(1.toShort()) // Type A
        bb.putShort(1.toShort()) // Class IN

        // Answer: pointer to 12 (0xC00C), Type A, Class IN, TTL 300, RdLen 4, 8.8.8.8
        bb.putShort(0xC00C.toShort())
        bb.putShort(1.toShort()) // Type A
        bb.putShort(1.toShort()) // Class IN
        bb.putInt(300)           // TTL
        bb.putShort(4.toShort()) // RdLength
        bb.put(byteArrayOf(8, 8, 8, 8)) // IP 8.8.8.8

        val totalLen = bb.position()
        val response = ByteArray(totalLen)
        System.arraycopy(buffer, 0, response, 0, totalLen)

        // Matching ID and expected host should succeed
        val ipsMatch = DnsPacketEngine.parseDnsResponse(response, response.size, expectedId = queryId, expectedHost = host)
        assertEquals(1, ipsMatch.size)
        assertEquals("8.8.8.8", ipsMatch[0].hostAddress)

        // Mismatched ID should be rejected
        val ipsMismatch = DnsPacketEngine.parseDnsResponse(response, response.size, expectedId = 0x9999, expectedHost = host)
        assertTrue("Mismatched query ID must return empty list", ipsMismatch.isEmpty())

        // Mismatched QNAME should be rejected
        val ipsHostMismatch = DnsPacketEngine.parseDnsResponse(response, response.size, expectedId = queryId, expectedHost = "otherdomain.com")
        assertTrue("Mismatched QNAME host must return empty list", ipsHostMismatch.isEmpty())
    }

    @Test
    fun testSuspiciousIpFiltering() {
        val loopback = InetAddress.getByName("127.0.0.1")
        val blockedPage = InetAddress.getByName("10.10.10.10")
        val normalIp = InetAddress.getByName("8.8.8.8")

        assertTrue(DnsPacketEngine.isSuspicious(loopback, "google.com", 300))
        assertTrue(DnsPacketEngine.isSuspicious(blockedPage, "google.com", 300))
        assertFalse(DnsPacketEngine.isSuspicious(normalIp, "google.com", 300))

        // Low TTL spoofing detection
        assertTrue("TTL <= 1 must be marked as suspicious spoofing", DnsPacketEngine.isSuspicious(normalIp, "google.com", 1))
    }
}
