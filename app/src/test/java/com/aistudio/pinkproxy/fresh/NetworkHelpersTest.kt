package com.aistudio.pinkproxy.fresh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkHelpersTest {

    @Test
    fun testTlsParserNonTlsPacket() {
        val nonTls = byteArrayOf(0x00, 0x01, 0x02, 0x03, 0x04, 0x05)
        val offset = TlsParser.findSniOffset(nonTls, nonTls.size)
        assertEquals(-1, offset)
    }

    @Test
    fun testFakePacketHelperClientHello() {
        val host = "example.com"
        val fakePacket = FakePacketHelper.buildFakeClientHello(host, 50)
        
        assertTrue("Fake packet should be larger than 0", fakePacket.isNotEmpty())
        // Should start with TLS Handshake (0x16)
        assertEquals(0x16.toByte(), fakePacket[0])
        // Should contain the hostname
        val packetString = String(fakePacket, Charsets.US_ASCII)
        assertTrue("Packet should contain the hostname", packetString.contains(host))
    }
}
