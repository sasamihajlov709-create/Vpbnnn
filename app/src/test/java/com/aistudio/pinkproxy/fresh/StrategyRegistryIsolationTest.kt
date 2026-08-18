package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Test

class StrategyRegistryIsolationTest {

    @Test
    fun testAllBypassStrategiesHaveRealExecutors() {
        for (strategy in BypassStrategy.entries) {
            val isImplemented = StrategyExecutionRegistry.isActuallyImplemented(strategy)
            assertTrue("Strategy $strategy must be registered in StrategyExecutionRegistry", isImplemented)

            val executorType = StrategyExecutionRegistry.getExecutorType(strategy)
            assertNotNull("Strategy $strategy must have a non-null ExecutorType", executorType)

            val executor = StrategyExecutionRegistry.getExecutor(strategy)
            assertNotNull("Strategy $strategy must map to a valid StrategyExecutor", executor)
        }
    }

    @Test
    fun testTransportConsistency() {
        val tcpStrategies = StrategyExecutionRegistry.getSupportedStrategiesForTransport(TransportType.TCP)
        val udpStrategies = StrategyExecutionRegistry.getSupportedStrategiesForTransport(TransportType.UDP)
        val dnsStrategies = StrategyExecutionRegistry.getSupportedStrategiesForTransport(TransportType.DNS)

        assertTrue("Must have registered TCP strategies", tcpStrategies.isNotEmpty())
        assertTrue("Must have registered UDP strategies", udpStrategies.isNotEmpty())
        assertTrue("Must have registered DNS strategies", dnsStrategies.isNotEmpty())

        for (strat in udpStrategies) {
            assertTrue(
                "UDP strategy $strat must be family compatible with UDP",
                DpiStrategySelector.isFamilyCompatible(strat.family, TransportType.UDP)
            )
        }

        for (strat in dnsStrategies) {
            assertTrue(
                "DNS strategy $strat must be family compatible with DNS",
                DpiStrategySelector.isFamilyCompatible(strat.family, TransportType.DNS)
            )
        }
    }
}
