package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket

@OptIn(ExperimentalCoroutinesApi::class)
class BypassApplierTest {

    @Test
    fun testIsProbableHttpAndTlsDetection() {
        val httpGet = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray(Charsets.US_ASCII)
        assertTrue(BypassApplier.isProbableHttp(httpGet, httpGet.size))
        assertFalse(BypassApplier.isProbableTls(httpGet, httpGet.size))

        // TLS 1.2 / 1.3 ClientHello record header: 0x16, 0x03, 0x01 / 0x03
        val tlsClientHello = byteArrayOf(0x16.toByte(), 0x03.toByte(), 0x01.toByte(), 0x00.toByte(), 0x20.toByte(), 0x01.toByte(), 0x00.toByte())
        assertTrue(BypassApplier.isProbableTls(tlsClientHello, tlsClientHello.size))
        assertFalse(BypassApplier.isProbableHttp(tlsClientHello, tlsClientHello.size))

        val shortData = byteArrayOf(0x01, 0x02)
        assertFalse(BypassApplier.isProbableHttp(shortData, shortData.size))
        assertFalse(BypassApplier.isProbableTls(shortData, shortData.size))
    }

    @Test
    fun testCalculateRttAdaptiveDelayBounds() {
        val delayLowRtt = BypassApplier.calculateRttAdaptiveDelay(20L)
        assertTrue("Low RTT delay should be >= 2ms", delayLowRtt in 2L..80L)

        val delayHighRtt = BypassApplier.calculateRttAdaptiveDelay(1200L)
        assertTrue("High RTT delay capped at maxMs 80ms", delayHighRtt <= 80L)

        val customDelay = BypassApplier.calculateRttAdaptiveDelay(50L, customDelay = 15L)
        assertEquals(15L, customDelay)
    }

    @Test
    fun testApplyBypassDirect() = runTest {
        val testData = "Hello Network World".toByteArray()
        val outStream = ByteArrayOutputStream()
        val mockSocket = Socket()
        val config = SessionConfig(
            strategy = BypassStrategy.DIRECT,
            frag1 = 1,
            frag2 = 1,
            delay1 = 0,
            delay2 = 0,
            fakeTtl = 3,
            mss = 1300
        )

        BypassApplier.applyBypass(mockSocket, outStream, testData, testData.size, config, "example.com")
        val written = outStream.toByteArray()
        assertArrayEquals(testData, written)
    }
}
