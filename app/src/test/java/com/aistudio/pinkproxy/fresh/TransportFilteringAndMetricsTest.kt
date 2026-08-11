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
        }
    }

    @Test
    fun testFamilyCompatibilityHelper() {
        assertTrue(DpiStrategySelector.isFamilyCompatible(StrategyFamily.TCP, TransportType.TCP))
        assertTrue(DpiStrategySelector.isFamilyCompatible(StrategyFamily.TLS, TransportType.TCP))
        assertFalse(DpiStrategySelector.isFamilyCompatible(StrategyFamily.UDP, TransportType.TCP))
        assertFalse(DpiStrategySelector.isFamilyCompatible(StrategyFamily.QUIC, TransportType.TCP))

        assertTrue(DpiStrategySelector.isFamilyCompatible(StrategyFamily.UDP, TransportType.UDP))
        assertTrue(DpiStrategySelector.isFamilyCompatible(StrategyFamily.QUIC, TransportType.UDP))
        assertFalse(DpiStrategySelector.isFamilyCompatible(StrategyFamily.TCP, TransportType.UDP))
        assertFalse(DpiStrategySelector.isFamilyCompatible(StrategyFamily.TLS, TransportType.UDP))
    }
}
