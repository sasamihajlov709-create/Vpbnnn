package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class DpiStrategySelectorTest {

    @Before
    fun setUp() {
        DpiEngine.resetStrategyScoresForNetworkChange()
    }

    @Test
    fun testIsFamilyCompatibleForTransports() {
        assertTrue(DpiStrategySelector.isFamilyCompatible(StrategyFamily.TCP, TransportType.TCP))
        assertTrue(DpiStrategySelector.isFamilyCompatible(StrategyFamily.TLS, TransportType.TCP))
        assertTrue(DpiStrategySelector.isFamilyCompatible(StrategyFamily.HTTP, TransportType.TCP))
        assertTrue(DpiStrategySelector.isFamilyCompatible(StrategyFamily.FRAGMENTATION, TransportType.TCP))
        assertFalse(DpiStrategySelector.isFamilyCompatible(StrategyFamily.UDP, TransportType.TCP))

        assertTrue(DpiStrategySelector.isFamilyCompatible(StrategyFamily.UDP, TransportType.UDP))
        assertTrue(DpiStrategySelector.isFamilyCompatible(StrategyFamily.QUIC, TransportType.UDP))
        assertFalse(DpiStrategySelector.isFamilyCompatible(StrategyFamily.TCP, TransportType.UDP))

        assertTrue(DpiStrategySelector.isFamilyCompatible(StrategyFamily.DNS, TransportType.DNS))
        assertFalse(DpiStrategySelector.isFamilyCompatible(StrategyFamily.TLS, TransportType.DNS))
    }

    @Test
    fun testGetDefaultFallbacks() {
        val tcpFallback = DpiStrategySelector.getDefaultFallback(TransportType.TCP)
        assertEquals(BypassStrategy.SNI_SPLIT, tcpFallback)

        val udpFallback = DpiStrategySelector.getDefaultFallback(TransportType.UDP)
        assertEquals(BypassStrategy.UDP_COMBINED_HYBRID, udpFallback)

        val dnsFallback = DpiStrategySelector.getDefaultFallback(TransportType.DNS)
        assertEquals(BypassStrategy.DNS_OVER_TCP, dnsFallback)
    }

    @Test
    fun testGetBestStrategyReturnsValidExecutorSupportedStrategy() {
        val strategyTcp = DpiStrategySelector.getBestStrategy(HostCategory.STREAMING, "youtube.com", TransportType.TCP)
        assertTrue(StrategyExecutionRegistry.isExecutorSupported(strategyTcp, TransportType.TCP))
        assertTrue(DpiStrategySelector.isFamilyCompatible(strategyTcp.family, TransportType.TCP))

        val strategyUdp = DpiStrategySelector.getBestStrategy(HostCategory.MESSENGER, "discord.com", TransportType.UDP)
        assertTrue(StrategyExecutionRegistry.isExecutorSupported(strategyUdp, TransportType.UDP))
        assertTrue(DpiStrategySelector.isFamilyCompatible(strategyUdp.family, TransportType.UDP))

        val strategyDns = DpiStrategySelector.getBestStrategy(HostCategory.OTHER, "dns.google", TransportType.DNS)
        assertTrue(StrategyExecutionRegistry.isExecutorSupported(strategyDns, TransportType.DNS))
        assertTrue(DpiStrategySelector.isFamilyCompatible(strategyDns.family, TransportType.DNS))
    }
}
