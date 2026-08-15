package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Test

class AllStrategiesExecutorCoverageTest {

    @Test
    fun testEveryStrategyHasRegisteredAndImplementedExecutor() {
        val allStrategies = BypassStrategy.entries
        assertTrue("Total strategies should be > 200", allStrategies.size >= 220)

        val unmappedStrategies = mutableListOf<BypassStrategy>()
        val unexecutableStrategies = mutableListOf<String>()

        for (strategy in allStrategies) {
            val executorType = StrategyExecutionRegistry.getExecutorType(strategy)
            if (executorType == null) {
                unmappedStrategies.add(strategy)
                continue
            }

            val executor = StrategyExecutionRegistry.getExecutor(strategy)
            assertNotNull("Executor for $strategy ($executorType) must not be null", executor)

            if (!executor.supportsStrategy(strategy)) {
                unexecutableStrategies.add("$strategy -> ${executor.executorType}")
            }

            // Verify at least one transport is supported
            val supportedTransports = TransportType.entries.filter { transport ->
                StrategyExecutionRegistry.isExecutorSupported(strategy, transport)
            }
            assertTrue(
                "Strategy $strategy must support at least one valid transport",
                supportedTransports.isNotEmpty()
            )
        }

        assertTrue(
            "All strategies must be mapped in StrategyExecutionRegistry. Unmapped: $unmappedStrategies",
            unmappedStrategies.isEmpty()
        )
        assertTrue(
            "All strategies must be explicitly implemented by their executor. Unimplemented: $unexecutableStrategies",
            unexecutableStrategies.isEmpty()
        )
    }

    @Test
    fun testDeepExecutorCheckRejectsInvalidCombinations() {
        // DIRECT supports TCP, UDP, DNS
        assertTrue(StrategyExecutionRegistry.isExecutorSupported(BypassStrategy.DIRECT, TransportType.TCP))
        assertTrue(StrategyExecutionRegistry.isExecutorSupported(BypassStrategy.DIRECT, TransportType.UDP))
        assertTrue(StrategyExecutionRegistry.isExecutorSupported(BypassStrategy.DIRECT, TransportType.DNS))

        // TLS_SNI_SPLIT only supports TCP
        assertTrue(StrategyExecutionRegistry.isExecutorSupported(BypassStrategy.TLS_SNI_SPLIT, TransportType.TCP))
        assertFalse(StrategyExecutionRegistry.isExecutorSupported(BypassStrategy.TLS_SNI_SPLIT, TransportType.UDP))
        assertFalse(StrategyExecutionRegistry.isExecutorSupported(BypassStrategy.TLS_SNI_SPLIT, TransportType.DNS))

        // UDP_STUN_FAKE only supports UDP
        assertTrue(StrategyExecutionRegistry.isExecutorSupported(BypassStrategy.UDP_STUN_FAKE, TransportType.UDP))
        assertFalse(StrategyExecutionRegistry.isExecutorSupported(BypassStrategy.UDP_STUN_FAKE, TransportType.TCP))

        // DNS_OVER_QUIC supports DNS and UDP
        assertTrue(StrategyExecutionRegistry.isExecutorSupported(BypassStrategy.DNS_OVER_QUIC, TransportType.DNS))
        assertTrue(StrategyExecutionRegistry.isExecutorSupported(BypassStrategy.DNS_OVER_QUIC, TransportType.UDP))
        assertFalse(StrategyExecutionRegistry.isExecutorSupported(BypassStrategy.DNS_OVER_QUIC, TransportType.TCP))
    }

    @Test
    fun testDnsAndDoqExecutorsExecution() = kotlinx.coroutines.runBlocking {
        val testQuery = byteArrayOf(0x00, 0x1D, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01)
        val baos = java.io.ByteArrayOutputStream()
        val mockSocket = java.net.Socket()

        val tcpCtx = TcpExecutionContext(
            socket = mockSocket,
            output = baos,
            data = testQuery,
            length = testQuery.size,
            host = "example.com",
            strategy = BypassStrategy.DNS_OVER_TCP,
            config = SessionConfig(strategy = BypassStrategy.DNS_OVER_TCP, frag1 = 2, delay1 = 2L, fakeTtl = 0),
            effectiveDelayMs = 2L
        )

        StrategyExecutorDns.executeTcp(tcpCtx)
        val written = baos.toByteArray()
        assertTrue("TCP DNS should frame and write data", written.isNotEmpty())
        assertEquals(testQuery.size, written.size)

        // Test DoQ execution
        val mockUdpSocket = java.net.DatagramSocket()
        val udpCtx = UdpExecutionContext(
            socket = mockUdpSocket,
            address = java.net.InetAddress.getByName("127.0.0.1"),
            port = 8853,
            data = testQuery,
            length = testQuery.size,
            host = "example.com",
            strategy = BypassStrategy.DNS_OVER_QUIC,
            config = SessionConfig(strategy = BypassStrategy.DNS_OVER_QUIC, frag1 = 2, delay1 = 2L, fakeTtl = 0)
        )


        StrategyExecutorDoq.executeUdp(udpCtx)
        mockUdpSocket.close()
    }
}

