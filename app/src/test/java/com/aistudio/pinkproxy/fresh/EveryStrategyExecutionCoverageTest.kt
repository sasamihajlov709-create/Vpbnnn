package com.aistudio.pinkproxy.fresh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Stage 1 Verification Unit Test:
 * Enforces 100% executor coverage across all 225+ BypassStrategy enum values.
 * Guarantees that no strategy can be selected or loaded without a registered,
 * fully implemented executor and transport capability mapping.
 */
class EveryStrategyExecutionCoverageTest {

    @Test
    fun `verify every strategy enum has an explicit executor mapping`() {
        val allStrategies = BypassStrategy.entries
        val missingStrategies = mutableListOf<BypassStrategy>()

        for (strategy in allStrategies) {
            val isImplemented = StrategyExecutionRegistry.isActuallyImplemented(strategy)
            val executorType = StrategyExecutionRegistry.getExecutorType(strategy)
            if (!isImplemented || executorType == null) {
                missingStrategies.add(strategy)
            }
        }

        assertTrue(
            "The following strategies are missing an explicit executor mapping in StrategyExecutionRegistry: $missingStrategies",
            missingStrategies.isEmpty()
        )
    }

    @Test
    fun `verify every strategy supports at least one transport type`() {
        val allStrategies = BypassStrategy.entries
        val untransportable = mutableListOf<BypassStrategy>()

        for (strategy in allStrategies) {
            val tcpSupported = StrategyExecutionRegistry.isExecutorSupported(strategy, TransportType.TCP)
            val udpSupported = StrategyExecutionRegistry.isExecutorSupported(strategy, TransportType.UDP)
            val dnsSupported = StrategyExecutionRegistry.isExecutorSupported(strategy, TransportType.DNS)
            if (!tcpSupported && !udpSupported && !dnsSupported) {
                untransportable.add(strategy)
            }
        }

        assertTrue(
            "The following strategies do not declare support for TCP, UDP, or DNS in StrategyExecutionRegistry: $untransportable",
            untransportable.isEmpty()
        )
    }

    @Test
    fun `verify supported strategies query returns non-empty collections for TCP, UDP and DNS`() {
        val tcpStrategies = StrategyExecutionRegistry.getSupportedStrategiesForTransport(TransportType.TCP)
        val udpStrategies = StrategyExecutionRegistry.getSupportedStrategiesForTransport(TransportType.UDP)
        val dnsStrategies = StrategyExecutionRegistry.getSupportedStrategiesForTransport(TransportType.DNS)

        assertTrue("TCP strategies count should be substantial (> 100)", tcpStrategies.size > 100)
        assertTrue("UDP strategies count should be substantial (> 30)", udpStrategies.size > 30)
        assertTrue("DNS strategies count should be non-empty (>= 6)", dnsStrategies.size >= 6)

        // Ensure total unique strategies covered across all 3 transports equals total enum values
        val combined = (tcpStrategies + udpStrategies + dnsStrategies).toSet()
        assertEquals(
            "Every strategy in BypassStrategy must appear in either TCP, UDP, or DNS supported sets",
            BypassStrategy.entries.size,
            combined.size
        )
    }
}
