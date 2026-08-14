package com.aistudio.pinkproxy.fresh

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.nio.ByteBuffer

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class UdpQuicPipelineTest {

    @Test
    fun testStunPacketRecognition() {
        // Construct standard STUN Binding Request: Type=0x0001, Length=0, Magic Cookie=0x2112A442, Transaction ID=12 bytes
        val stun = ByteArray(20)
        val bb = ByteBuffer.wrap(stun)
        bb.putShort(0x0001.toShort()) // STUN Binding Request
        bb.putShort(0.toShort())      // Message length 0
        bb.putInt(0x2112A442)         // Magic cookie
        // 12 bytes TID

        assertTrue("Valid STUN packet must be detected", UdpTransportHandler.isStunPacket(stun))

        // Non-STUN packet
        val randomUdp = byteArrayOf(0x13, 0x37, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04)
        assertFalse("Arbitrary payload must not be identified as STUN", UdpTransportHandler.isStunPacket(randomUdp))
    }

    @Test
    fun testQuicBlockingPolicy() {
        val nonStunPayload = byteArrayOf(0xC0.toByte(), 0x00, 0x00, 0x01, 0x08) // Long header QUIC Initial packet

        // Discord/Telegram voice sessions or Messenger hosts should NEVER have QUIC/UDP blocked
        assertFalse(
            "Messenger voice sessions must never be blocked",
            UdpTransportHandler.shouldBlockQuicForHost("voice.discord.gg", 50000, nonStunPayload)
        )
        assertFalse(
            "Gaming UDP sessions must never be blocked",
            UdpTransportHandler.shouldBlockQuicForHost("game.steam.com", 27015, nonStunPayload)
        )

        // YouTube CDN endpoints should be blocked to force immediate 0ms fallback to HTTP/2/TCP bypass pipeline
        assertTrue(
            "YouTube CDN endpoints must block corrupted QUIC to force TCP pipeline",
            UdpTransportHandler.shouldBlockQuicForHost("rr1---sn-4g5ednss.googlevideo.com", 443, nonStunPayload)
        )
    }
}
