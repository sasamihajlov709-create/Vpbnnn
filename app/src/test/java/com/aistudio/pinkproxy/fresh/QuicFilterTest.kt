package com.aistudio.pinkproxy.fresh

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class QuicFilterTest {

    @Test
    fun `blockQuic flag toggles correctly in BypassConfig`() {
        BypassConfig.blockQuic = true
        assertTrue(BypassConfig.blockQuic)

        BypassConfig.blockQuic = false
        assertFalse(BypassConfig.blockQuic)
    }

    @Test
    fun `isQuicPacket detects UDP port and payload headers as QUIC`() {
        // Check port 443
        assertTrue(UdpTransportHandler.isQuicPacket(443, byteArrayOf()))
        assertTrue(UdpTransportHandler.isQuicPacket(8443, byteArrayOf()))

        // Non-443 port with QUIC long header bit (0x80)
        val quicLongHeaderPayload = byteArrayOf(0xC0.toByte(), 0x00, 0x00, 0x01)
        assertTrue(UdpTransportHandler.isQuicPacket(12345, quicLongHeaderPayload))

        // Non-443 port with regular non-QUIC UDP payload
        val regularUdpPayload = byteArrayOf(0x00, 0x01, 0x02, 0x03)
        assertFalse(UdpTransportHandler.isQuicPacket(12345, regularUdpPayload))
    }
}
