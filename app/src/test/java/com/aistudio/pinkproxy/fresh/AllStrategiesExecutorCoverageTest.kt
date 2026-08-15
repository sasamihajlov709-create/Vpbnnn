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
}
