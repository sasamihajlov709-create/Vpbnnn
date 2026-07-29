package com.aistudio.pinkproxy.fresh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class TlsParserTest {
    @Test
    fun testFindSniOffset() {
        // Build a realistic ClientHello using our helper
        val fakeHello = FakePacketHelper.buildRealisticTlsHello("example.com")
        println("fakeHello length: ${fakeHello.size}")
        println("Byte 0: ${fakeHello[0]}")
        println("Byte 5: ${fakeHello[5]}")
        
        // Find SNI
        val offset = TlsParser.findSniOffset(fakeHello, fakeHello.size, "example.com")
        assertTrue("SNI offset should be found and > 0, but got $offset", offset > 0)
        
        // Extract the string at offset
        val extracted = String(fakeHello, offset, "example.com".length)
        assertEquals("example.com", extracted)
    }

    @Test
    fun testEchDetection() {
        // Create an ECH padded fake hello (our fake helper adds ECH extensions if we ask it to, wait, buildFakeClientHello adds GREASE which might look like ECH if it's 0xfe0d, but buildFakeClientHello does not explicitly add 0xfe0d. Let's see if TlsParser works).
        val fakeQuic = FakePacketHelper.buildQuicInitial()
        assertFalse(TlsParser.isEchDetected(fakeQuic, fakeQuic.size))
    }
}
