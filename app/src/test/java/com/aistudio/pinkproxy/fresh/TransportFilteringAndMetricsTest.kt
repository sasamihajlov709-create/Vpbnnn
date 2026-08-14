package com.aistudio.pinkproxy.fresh

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class TransportFilteringAndMetricsTest {

    @Test
    fun testTcpAutoSelectionFiltersOutUdpAndQuicFamilies() {
        val host = "tcp-service-test.com"
        val category = HostCategory.STREAMING

        repeat(10) {
            val selected = DpiStrategySelector.getBestStrategy(category, host, TransportType.TCP)
            assertFalse(
                "TCP strategy selector must not return UDP strategy $selected",
                selected.family == StrategyFamily.UDP || selected.family == StrategyFamily.QUIC || selected.family == StrategyFamily.DNS
            )
        }
    }

    @Test
    fun testUdpAutoSelectionFiltersOutTcpAndTlsFamilies() {
        val host = "udp-service-test.com"
        val category = HostCategory.GAMING

        repeat(10) {
            val selected = DpiStrategySelector.getBestStrategy(category, host, TransportType.UDP)
            assertFalse(
                "UDP strategy selector must not return TCP/TLS strategy $selected",
                selected.family == StrategyFamily.TCP || selected.family == StrategyFamily.TLS || 
                selected.family == StrategyFamily.HTTP || selected.family == StrategyFamily.FRAGMENTATION || 
                selected.family == StrategyFamily.TIMING || selected.family == StrategyFamily.DNS
            )
            assertTrue(
                "UDP strategy must have a supported executor",
                StrategyExecutionRegistry.isExecutorSupported(selected, TransportType.UDP)
            )
        }
    }

    @Test
    fun testDnsAutoSelectionReturnsOnlyDnsCompatibleStrategies() {
        val host = "dns.google.com"
        val category = HostCategory.OTHER

        repeat(10) {
            val selected = DpiStrategySelector.getBestStrategy(category, host, TransportType.DNS)
            assertTrue(
                "DNS strategy must be family compatible with DNS",
                DpiStrategySelector.isFamilyCompatible(selected.family, TransportType.DNS)
            )
            assertTrue(
                "DNS strategy must have registered executor for DNS transport",
                StrategyExecutionRegistry.isExecutorSupported(selected, TransportType.DNS)
            )
        }
    }

    @Test
    fun testDiverseFallbackRespectsTransportAndExecutorContracts() {
        TransportType.entries.forEach { transport ->
            repeat(15) {
                val fallback = DpiStrategySelector.getDiverseFallback(transport = transport)
                assertTrue(
                    "Fallback $fallback must be family compatible with $transport",
                    DpiStrategySelector.isFamilyCompatible(fallback.family, transport)
                )
                assertTrue(
                    "Fallback $fallback must have supported executor for $transport",
                    StrategyExecutionRegistry.isExecutorSupported(fallback, transport)
                )
            }
        }
    }

    @Test
    fun testExtremeStrategyRespectsTransportContracts() {
        TransportType.entries.forEach { transport ->
            val extreme = DpiStrategySelector.getBestExtremeStrategy(transport = transport)
            assertTrue(
                "Extreme $extreme must be family compatible with $transport",
                DpiStrategySelector.isFamilyCompatible(extreme.family, transport)
            )
            assertTrue(
                "Extreme $extreme must have supported executor for $transport",
                StrategyExecutionRegistry.isExecutorSupported(extreme, transport)
            )
        }
    }

    @Test
    fun testFamilyCompatibilityHelper() {
        assertTrue(DpiStrategySelector.isFamilyCompatible(StrategyFamily.TCP, TransportType.TCP))
        assertTrue(DpiStrategySelector.isFamilyCompatible(StrategyFamily.TLS, TransportType.TCP))
        assertFalse(DpiStrategySelector.isFamilyCompatible(StrategyFamily.UDP, TransportType.TCP))
        assertFalse(DpiStrategySelector.isFamilyCompatible(StrategyFamily.QUIC, TransportType.TCP))
        assertFalse(DpiStrategySelector.isFamilyCompatible(StrategyFamily.DNS, TransportType.TCP))

        assertTrue(DpiStrategySelector.isFamilyCompatible(StrategyFamily.UDP, TransportType.UDP))
        assertTrue(DpiStrategySelector.isFamilyCompatible(StrategyFamily.QUIC, TransportType.UDP))
        assertFalse(DpiStrategySelector.isFamilyCompatible(StrategyFamily.TCP, TransportType.UDP))
        assertFalse(DpiStrategySelector.isFamilyCompatible(StrategyFamily.TLS, TransportType.UDP))
        assertFalse(DpiStrategySelector.isFamilyCompatible(StrategyFamily.DNS, TransportType.UDP))

        assertTrue(DpiStrategySelector.isFamilyCompatible(StrategyFamily.DNS, TransportType.DNS))
        assertTrue(DpiStrategySelector.isFamilyCompatible(StrategyFamily.DIRECT, TransportType.DNS))
        assertFalse(DpiStrategySelector.isFamilyCompatible(StrategyFamily.TCP, TransportType.DNS))
        assertFalse(DpiStrategySelector.isFamilyCompatible(StrategyFamily.UDP, TransportType.DNS))
        assertFalse(DpiStrategySelector.isFamilyCompatible(StrategyFamily.TLS, TransportType.DNS))
    }

    @Test
    fun testAllStrategiesHaveValidRegisteredExecutors() {
        BypassStrategy.entries.forEach { strategy ->
            assertTrue(
                "Strategy $strategy must be registered in StrategyExecutionRegistry",
                StrategyExecutionRegistry.isActuallyImplemented(strategy)
            )
            val executor = StrategyExecutionRegistry.getExecutor(strategy)
            assertTrue(
                "Executor for $strategy must claim support for it",
                executor.supportsStrategy(strategy)
            )
        }
    }

    @Test
    fun testStrategyFallbackChainsAreStrictlyImplementedAndCompatible() {
        DpiEngine.strategyChains.forEach { (source, fallback) ->
            assertTrue(
                "Source strategy $source must have registered executor",
                StrategyExecutionRegistry.isActuallyImplemented(source)
            )
            assertTrue(
                "Fallback strategy $fallback must have registered executor",
                StrategyExecutionRegistry.isActuallyImplemented(fallback)
            )
            val sourceTransports = StrategyExecutionRegistry.getSupportedStrategiesForTransport(TransportType.TCP).contains(source)
            if (sourceTransports) {
                val fallbackViaSelector = DpiStrategySelector.getFallbackStrategy(source, TransportType.TCP)
                assertTrue(
                    "TCP fallback for $source must be compatible and non-null",
                    fallbackViaSelector != null && StrategyExecutionRegistry.isExecutorSupported(fallbackViaSelector, TransportType.TCP)
                )
            }
        }
    }
}

