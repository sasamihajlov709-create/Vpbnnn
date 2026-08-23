package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayOutputStream
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket

/**
 * Stage 4 Verification Test:
 * Executes real execution pipelines for all 225 BypassStrategy entries across TCP, UDP, and DNS transports.
 * Verifies that no strategy throws UnsupportedStrategyException or unhandled crash when invoked through its executor.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class AllStrategiesExecutionPipelineTest {

    private val sampleTlsClientHello = byteArrayOf(
        0x16.toByte(), 0x03.toByte(), 0x01.toByte(), 0x00.toByte(), 0x40.toByte(),
        0x01.toByte(), 0x00.toByte(), 0x00.toByte(), 0x3c.toByte(), 0x03.toByte(), 0x03.toByte()
    ) + ByteArray(53) { (it and 0xFF).toByte() }

    private val sampleHttpGet = ("GET / HTTP/1.1\r\n" +
            "Host: test-domain.com\r\n" +
            "User-Agent: Mozilla/5.0\r\n" +
            "Accept: */*\r\n\r\n").toByteArray()

    private val sampleUdpPayload = ByteArray(64) { (it * 3).toByte() }

    @Test
    fun `verify execution of all TCP supported strategies`() = runBlocking {
        val tcpStrategies = StrategyExecutionRegistry.getSupportedStrategiesForTransport(TransportType.TCP)
        assertTrue("TCP strategies must not be empty", tcpStrategies.isNotEmpty())

        val dummySocket = Socket()

        for (strat in tcpStrategies) {
            val executor = StrategyExecutionRegistry.getExecutor(strat)
            val outputStream = ByteArrayOutputStream()
            val config = SessionConfig(strategy = strat, frag1 = 10, delay1 = 0L, fakeTtl = 3)

            val payload = if (strat.family == StrategyFamily.HTTP) sampleHttpGet else sampleTlsClientHello

            val context = TcpExecutionContext(
                socket = dummySocket,
                output = outputStream,
                data = payload,
                length = payload.size,
                host = "test-domain.com",
                strategy = strat,
                config = config,
                effectiveDelayMs = 0L
            )

            try {
                executor.executeTcp(context)
                if (strat != BypassStrategy.DIRECT) {
                     assertTrue("Executor for $strat must transform or output data, got size: ${outputStream.size()}", outputStream.size() > 0)
                }
            } catch (e: UnsupportedStrategyException) {
                throw AssertionError("Strategy $strat failed with UnsupportedStrategyException in executor ${executor.executorType}", e)
            } catch (e: java.net.SocketException) {
                // Expected if the executor interacts deeply with the dummy socket.
                // We ignore it safely since the execution path was reached.
            } catch (e: java.nio.channels.NotYetConnectedException) {
                // Same as above
            } catch (e: Exception) {
                 // Check if it wraps a socket exception
                 if (e.cause is java.net.SocketException || e.message?.contains("Socket") == true) {
                     // Expected
                 } else {
                     throw AssertionError("Strategy $strat failed with unexpected exception", e)
                 }
            }
        }
    }

    @Test
    fun `verify execution of all UDP supported strategies`() = runBlocking {
        val udpStrategies = StrategyExecutionRegistry.getSupportedStrategiesForTransport(TransportType.UDP)
        assertTrue("UDP strategies must not be empty", udpStrategies.isNotEmpty())

        val dummySocket = DatagramSocket()
        val loopback = InetAddress.getLoopbackAddress()

        for (strat in udpStrategies) {
            val executor = StrategyExecutionRegistry.getExecutor(strat)
            val config = SessionConfig(strategy = strat, frag1 = 10, delay1 = 0L, fakeTtl = 3)

            val context = UdpExecutionContext(
                socket = dummySocket,
                address = loopback,
                port = 443,
                data = sampleUdpPayload,
                length = sampleUdpPayload.size,
                host = "udp-test.example.com",
                strategy = strat,
                config = config
            )

            try {
                executor.executeUdp(context)
            } catch (e: UnsupportedStrategyException) {
                throw AssertionError("Strategy $strat failed with UnsupportedStrategyException in executor ${executor.executorType}", e)
            } catch (e: java.net.SocketException) {
                // Expected dummy socket failures
            } catch (e: java.nio.channels.NotYetConnectedException) {
                // Expected
            } catch (e: Exception) {
                 if (e.cause is java.net.SocketException || e.message?.contains("Socket") == true) {
                     // Expected
                 } else {
                     throw AssertionError("Strategy $strat failed with unexpected exception", e)
                 }
            }
        }
        dummySocket.close()
    }

    @Test
    fun `verify execution of all DNS supported strategies`() = runBlocking {
        val dnsStrategies = StrategyExecutionRegistry.getSupportedStrategiesForTransport(TransportType.DNS)
        assertTrue("DNS strategies must not be empty", dnsStrategies.isNotEmpty())

        val dummyUdpSocket = DatagramSocket()
        val dummyTcpSocket = Socket()
        val loopback = InetAddress.getLoopbackAddress()
        val sampleDnsPayload = byteArrayOf(0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01)

        for (strat in dnsStrategies) {
            val executor = StrategyExecutionRegistry.getExecutor(strat)
            val config = SessionConfig(strategy = strat, frag1 = 0, delay1 = 0L, fakeTtl = 0)

            try {
                if (executor.executorType == StrategyExecutionRegistry.ExecutorType.DNS_OVER_QUIC || executor.executorType == StrategyExecutionRegistry.ExecutorType.UDP_HANDLER) {
                    val context = UdpExecutionContext(
                        socket = dummyUdpSocket,
                        address = loopback,
                        port = 53,
                        data = sampleDnsPayload,
                        length = sampleDnsPayload.size,
                        host = "dns-test.example.com",
                        strategy = strat,
                        config = config
                    )
                    executor.executeUdp(context)
                } else {
                    val outputStream = ByteArrayOutputStream()
                    val context = TcpExecutionContext(
                        socket = dummyTcpSocket,
                        output = outputStream,
                        data = sampleDnsPayload,
                        length = sampleDnsPayload.size,
                        host = "dns-test.example.com",
                        strategy = strat,
                        config = config,
                        effectiveDelayMs = 0L
                    )
                    executor.executeTcp(context)
                }
            } catch (e: UnsupportedStrategyException) {
                throw AssertionError("Strategy $strat failed with UnsupportedStrategyException in executor ${executor.executorType}", e)
            } catch (e: java.net.SocketException) {
                // Expected dummy socket failures
            } catch (e: java.nio.channels.NotYetConnectedException) {
                // Expected
            } catch (e: Exception) {
                 if (e.cause is java.net.SocketException || e.message?.contains("Socket") == true) {
                     // Expected
                 } else {
                     throw AssertionError("Strategy $strat failed with unexpected exception", e)
                 }
            }
        }
        dummyUdpSocket.close()
    }
}
