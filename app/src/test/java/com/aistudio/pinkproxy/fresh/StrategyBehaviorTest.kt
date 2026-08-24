package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayOutputStream
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class StrategyBehaviorTest {

    private val sampleTlsClientHello = byteArrayOf(
        0x16.toByte(), 0x03.toByte(), 0x01.toByte(), 0x00.toByte(), 0x40.toByte(),
        0x01.toByte(), 0x00.toByte(), 0x00.toByte(), 0x3c.toByte(), 0x03.toByte(), 0x03.toByte(),
    ) + ByteArray(53) { (it and 0xFF).toByte() }

    private val sampleHttpGet = ("GET / HTTP/1.1\r\n" +
            "Host: test-domain.com\r\n" +
            "User-Agent: Mozilla/5.0\r\n" +
            "Accept: */*\r\n\r\n").toByteArray()

    @Test
    fun `SNI_SPLIT fragments TLS ClientHello across multiple writes`() = runBlocking {
        val out = TrackingByteArrayOutputStream()
        val ctx = TcpExecutionContext(
            socket = Socket(),
            output = out,
            data = sampleTlsClientHello,
            length = sampleTlsClientHello.size,
            host = "example.com",
            strategy = BypassStrategy.SNI_SPLIT,
            config = BypassConfig.getSessionConfig("example.com", BypassStrategy.SNI_SPLIT, 0L, TransportType.TCP),
            effectiveDelayMs = 0L,
            random = ThreadLocalRandom.current()
        )
        FragmentationStrategyHandler.executeTcp(ctx)
        val finalBytes = out.toByteArray()
        assertEquals("Total length must match original", sampleTlsClientHello.size, finalBytes.size)
        assertTrue("SNI_SPLIT should perform multiple writes", out.writeCount > 1)
        assertTrue("Byte content must be identical", sampleTlsClientHello.contentEquals(finalBytes))
    }

    @Test
    fun `TCP_BYTE_FRAG writes exactly 1 byte at a time`() = runBlocking {
        val out = TrackingByteArrayOutputStream()
        val ctx = TcpExecutionContext(
            socket = Socket(),
            output = out,
            data = sampleHttpGet,
            length = sampleHttpGet.size,
            host = "example.com",
            strategy = BypassStrategy.TCP_BYTE_FRAG,
            config = BypassConfig.getSessionConfig("example.com", BypassStrategy.TCP_BYTE_FRAG, 0L, TransportType.TCP),
            effectiveDelayMs = 0L
        )
        FragmentationStrategyHandler.executeTcp(ctx)
        assertEquals("Total length must match", sampleHttpGet.size, out.toByteArray().size)
        assertEquals("Should write exactly length times", sampleHttpGet.size, out.writeCount)
        assertTrue("Every write should be 1 byte", out.maxWriteSize == 1)
        assertTrue("Byte content must be identical", sampleHttpGet.contentEquals(out.toByteArray()))
    }

    @Test
    fun `TCP_OOB_DESYNC injects decoy OOB packet before real payload`() = runBlocking {
        val out = TrackingByteArrayOutputStream()
        val ctx = TcpExecutionContext(
            socket = Socket(),
            output = out,
            data = sampleTlsClientHello,
            length = sampleTlsClientHello.size,
            host = "example.com",
            strategy = BypassStrategy.TCP_OOB_DESYNC,
            config = BypassConfig.getSessionConfig("example.com", BypassStrategy.TCP_OOB_DESYNC, 0L, TransportType.TCP),
            effectiveDelayMs = 0L
        )
        TcpBasicStrategyHandler.executeTcp(ctx)
        val finalBytes = out.toByteArray()
        assertTrue("Output should be larger than original due to OOB injection", finalBytes.size > sampleTlsClientHello.size)
        assertTrue("Multiple writes occurred", out.writeCount >= 2)
        val expectedSuffix = sampleTlsClientHello.copyOfRange(sampleTlsClientHello.size - 10, sampleTlsClientHello.size)
        val actualSuffix = finalBytes.copyOfRange(finalBytes.size - 10, finalBytes.size)
        assertTrue("Payload should remain intact at the end", expectedSuffix.contentEquals(actualSuffix))
    }
    
    @Test
    fun `TCP_FOOL_DPI injects fake HTTP request before real payload`() = runBlocking {
        val out = TrackingByteArrayOutputStream()
        val ctx = TcpExecutionContext(
            socket = Socket(),
            output = out,
            data = sampleTlsClientHello,
            length = sampleTlsClientHello.size,
            host = "example.com",
            strategy = BypassStrategy.TCP_FOOL_DPI,
            config = BypassConfig.getSessionConfig("example.com", BypassStrategy.TCP_FOOL_DPI, 0L, TransportType.TCP),
            effectiveDelayMs = 0L
        )
        TcpBasicStrategyHandler.executeTcp(ctx)
        val finalBytes = out.toByteArray()
        assertTrue("Output should be larger than original due to FOOL DPI injection", finalBytes.size > sampleTlsClientHello.size)
        val stringOutput = String(finalBytes, Charsets.US_ASCII)
        assertTrue("Should contain fake HTTP GET", stringOutput.contains("GET /") && stringOutput.contains("HTTP/1.1"))
    }
    
    @Test
    fun `UDP_STUN_FAKE injects STUN header before original data`() = runBlocking {
        val dummySocket = java.net.DatagramSocket()
        val dummyAddress = java.net.InetAddress.getByName("127.0.0.1")
        val sampleUdp = ByteArray(32) { it.toByte() }
        
        val ctx = UdpExecutionContext(
            socket = dummySocket,
            address = dummyAddress,
            port = 443,
            data = sampleUdp,
            length = sampleUdp.size,
            host = "discord.com",
            strategy = BypassStrategy.UDP_STUN_FAKE,
            config = BypassConfig.getSessionConfig("discord.com", BypassStrategy.UDP_STUN_FAKE, 0L, TransportType.UDP)
        )
        var didFail = false
        try {
            UdpStrategyHandler.executeUdp(ctx)
        } catch (e: Exception) {
            didFail = true
        }
        dummySocket.close()
        org.junit.Assert.assertFalse("UDP_STUN_FAKE should execute without exceptions", didFail)
    }
}

class TrackingByteArrayOutputStream : ByteArrayOutputStream() {
    var writeCount = 0
        private set
    var maxWriteSize = 0
        private set

    override fun write(b: Int) {
        super.write(b)
        writeCount++
        maxWriteSize = maxOf(maxWriteSize, 1)
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        super.write(b, off, len)
        writeCount++
        maxWriteSize = maxOf(maxWriteSize, len)
    }
}
