package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.ThreadLocalRandom

class EvasionPacketManglerTest {

    @Test
    fun testMangleHttpMethodCase() {
        val httpGet = "GET /index.html HTTP/1.1\r\n".toByteArray(Charsets.US_ASCII)
        val mangled = EvasionPacketMangler.mangleHttpMethodCase(httpGet, httpGet.size)
        val text = String(mangled, Charsets.US_ASCII)
        assertTrue(text.contains("/index.html HTTP/1.1"))
    }

    @Test
    fun testAddSpaceToHttpMethod() {
        val httpGet = "POST /api/v1 HTTP/1.1\r\n".toByteArray(Charsets.US_ASCII)
        val spaced = EvasionPacketMangler.addSpaceToHttpMethod(httpGet, httpGet.size)
        val text = String(spaced, Charsets.US_ASCII)
        assertTrue(text.startsWith("POST  /api/v1"))
    }

    @Test
    fun testAddDotToHost() {
        val req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray(Charsets.US_ASCII)
        val mangled = EvasionPacketMangler.addDotToHost(req, req.size)
        val text = String(mangled, Charsets.US_ASCII)
        assertTrue(text.contains("Host: example.com.\r\n"))
    }

    @Test
    fun testSplitIntoTlsRecords() {
        val fakeTlsClientHello = ByteArray(120)
        fakeTlsClientHello[0] = 0x16.toByte() // Handshake
        fakeTlsClientHello[1] = 0x03.toByte() // Major
        fakeTlsClientHello[2] = 0x03.toByte() // Minor
        fakeTlsClientHello[3] = 0x00.toByte()
        fakeTlsClientHello[4] = 115.toByte() // Length

        for (i in 5 until 120) {
            fakeTlsClientHello[i] = (i and 0xFF).toByte()
        }

        val records = EvasionPacketMangler.splitIntoTlsRecords(fakeTlsClientHello, 120, 20)
        assertEquals(2, records.size)

        // Record 1
        assertEquals(0x16.toByte(), records[0][0])
        assertEquals(5 + 20, records[0].size)

        // Record 2
        assertEquals(0x16.toByte(), records[1][0])
        assertEquals(5 + (115 - 20), records[1].size)
    }

    @Test
    fun testCreateFakeTlsNoisePrefixHasRandomBytes() {
        val prefix = EvasionPacketMangler.createFakeTlsNoisePrefix()
        assertTrue(prefix.size >= 5 + 16)
        assertEquals(0x17.toByte(), prefix[0]) // TLS App Data
        assertEquals(0x03.toByte(), prefix[1]) // Major
        assertEquals(0x03.toByte(), prefix[2]) // Minor

        // Verify that payload bytes are not all zeros
        var nonZeroCount = 0
        for (i in 5 until prefix.size) {
            if (prefix[i] != 0.toByte()) {
                nonZeroCount++
            }
        }
        assertTrue("Noise payload must contain non-zero random bytes", nonZeroCount > 0)
    }
}
