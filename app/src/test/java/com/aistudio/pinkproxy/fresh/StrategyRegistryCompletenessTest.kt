package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Test

class StrategyRegistryCompletenessTest {

    @Test
    fun testAllBypassStrategiesHaveRegistryEntry() {
        val totalStrategies = BypassStrategy.entries.size
        assertTrue("Strategies count should be greater than 200", totalStrategies >= 225)

        for (strategy in BypassStrategy.entries) {
            assertTrue(
                "Strategy $strategy must be registered in StrategyExecutionRegistry",
                StrategyExecutionRegistry.isActuallyImplemented(strategy)
            )

            val executorType = StrategyExecutionRegistry.getExecutorType(strategy)
            assertNotNull("ExecutorType for $strategy must not be null", executorType)

            val executor = StrategyExecutionRegistry.getExecutor(strategy)
            assertNotNull("Executor instance for $strategy must not be null", executor)
            assertTrue(
                "Executor $executor must support strategy $strategy",
                executor.supportsStrategy(strategy)
            )
        }
    }

    @Test
    fun testTransportCompatibilityForEveryStrategy() {
        var tcpCount = 0
        var udpCount = 0
        var dnsCount = 0

        for (strategy in BypassStrategy.entries) {
            val supportedTransports = TransportType.entries.filter {
                StrategyExecutionRegistry.isExecutorSupported(strategy, it)
            }
            assertTrue("Strategy $strategy must support at least one transport", supportedTransports.isNotEmpty())

            if (supportedTransports.contains(TransportType.TCP)) tcpCount++
            if (supportedTransports.contains(TransportType.UDP)) udpCount++
            if (supportedTransports.contains(TransportType.DNS)) dnsCount++
        }

        assertTrue("TCP strategies should be majority", tcpCount > 150)
        assertTrue("UDP strategies must be present", udpCount > 20)
        assertTrue("DNS strategies must be present", dnsCount >= 6)
    }

    @Test
    fun testFamilyCompatibilityCoherence() {
        for (strategy in BypassStrategy.entries) {
            for (transport in TransportType.entries) {
                val isSupported = StrategyExecutionRegistry.isExecutorSupported(strategy, transport)
                if (isSupported) {
                    assertTrue(
                        "Strategy $strategy family ${strategy.family} must be compatible with transport $transport",
                        DpiStrategySelector.isFamilyCompatible(strategy.family, transport)
                    )
                }
            }
        }
    }
}
