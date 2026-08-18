package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Test

class FakePacketHelperTest {

    @Test
    fun testBuildRealisticTlsHello() {
        val host = "video.googlevideo.com"
        val hello = FakePacketHelper.buildRealisticTlsHello(host)
        assertTrue("Hello packet should not be empty", hello.isNotEmpty())
        assertEquals("TLS Handshake content type is 0x16", 0x16.toByte(), hello[0])
        assertEquals("TLS Major version is 3", 0x03.toByte(), hello[1])
    }

    @Test
    fun testBuildFakeHttpRequest() {
        val host = "blocked-domain.com"
        val request = FakePacketHelper.buildFakeHttpRequest(host)
        val requestStr = String(request, Charsets.US_ASCII)
        assertTrue(requestStr.startsWith("GET /"))
        assertTrue(requestStr.contains(" HTTP/1.1\r\n"))
        assertTrue(requestStr.contains("Host: $host"))
    }

    @Test
    fun testBuildProtocolConfusionVariants() {
        val ssh = FakePacketHelper.buildProtocolConfusion("SSH")
        assertTrue(String(ssh).startsWith("SSH-2.0"))

        val stun = FakePacketHelper.buildProtocolConfusion("STUN")
        assertTrue(stun.size >= 20)

        val wireguard = FakePacketHelper.buildWireguardFake()
        assertEquals(148, wireguard.size)
        assertEquals(0x01.toByte(), wireguard[0])

        val dtls = FakePacketHelper.buildDtlsClientHello()
        assertTrue(dtls.isNotEmpty())
        assertEquals(0x16.toByte(), dtls[0])
    }

    @Test
    fun testNoiseGeneratorBounds() {
        val noise64 = FakePacketHelper.buildUdpNoise(64)
        assertEquals(64, noise64.size)

        val smallNoise = FakePacketHelper.getSmallNoise(16)
        assertEquals(16, smallNoise.size)
    }
}
