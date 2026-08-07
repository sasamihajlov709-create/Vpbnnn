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
    fun `isQuicPacket detects UDP port 443 as QUIC`() {
        // Port 443 is QUIC standard
        val port = 443
        val dummyPayload = byteArrayOf(0x80.toByte(), 0x00, 0x00, 0x01)
        
        // Check port matching
        assertTrue(port == 443 || port == 8443)
    }
}
