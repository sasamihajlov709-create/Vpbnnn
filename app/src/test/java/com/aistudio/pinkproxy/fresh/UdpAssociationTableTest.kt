package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress

class UdpAssociationTableTest {

    @Test
    fun testSessionCreationAndTouch() {
        val clientIp = InetAddress.getByName("127.0.0.1")
        val clientPort = 55432
        val targetHost = "example.com"
        val targetPort = 443

        UdpAssociationTable.clear()

        val session = UdpAssociationTable.getOrCreateSession(
            clientAddress = clientIp,
            clientPort = clientPort,
            destinationHost = targetHost,
            destinationPort = targetPort,
            strategy = BypassStrategy.FAKE_PACKET
        )

        assertNotNull(session)
        assertEquals(targetHost, session.key.destinationHost)
        assertEquals(clientPort, session.key.clientPort)

        UdpAssociationTable.touchSession(session.key, sentBytes = 120, receivedBytes = 250)

        assertEquals(1L, session.packetsSent)
        assertEquals(120L, session.bytesSent)
        assertEquals(1L, session.packetsReceived)
        assertEquals(250L, session.bytesReceived)
    }

    @Test
    fun testSessionEndpointMapping() {
        val clientIp = InetAddress.getByName("127.0.0.1")
        val clientPort = 49152
        val targetHost = "93.184.216.34"
        val targetPort = 443

        UdpAssociationTable.clear()

        val session = UdpAssociationTable.getOrCreateSession(
            clientAddress = clientIp,
            clientPort = clientPort,
            destinationHost = targetHost,
            destinationPort = targetPort,
            strategy = BypassStrategy.DIRECT
        )

        val endpointKey = "93.184.216.34:443"
        UdpAssociationTable.bindEndpoint(endpointKey, session.key)

        val foundKey = UdpAssociationTable.findClientForKey(endpointKey)
        assertNotNull(foundKey)
        assertEquals(clientPort, foundKey?.clientPort)
    }

    @Test
    fun testQuicPacketDetection() {
        val stunPayload = ByteArray(24) { 0 }
        stunPayload[4] = 0x21.toByte()
        stunPayload[5] = 0x12.toByte()
        stunPayload[6] = 0xA4.toByte()
        stunPayload[7] = 0x42.toByte()

        assertTrue(UdpTransportHandler.isStunPacket(stunPayload))
        assertFalse(UdpTransportHandler.shouldBlockQuicForHost("discord.gg", 50000, stunPayload))

        // QUIC Long Header Initial packet (first byte 0xC0 or 0x80)
        val quicInitial = ByteArray(1200) { 0 }
        quicInitial[0] = 0xC0.toByte()
        assertTrue(UdpTransportHandler.isQuicPacket(443, quicInitial))
    }
}
