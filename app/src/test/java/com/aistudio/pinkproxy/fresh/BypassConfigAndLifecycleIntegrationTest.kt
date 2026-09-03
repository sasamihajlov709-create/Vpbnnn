package com.aistudio.pinkproxy.fresh

import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class BypassConfigAndLifecycleIntegrationTest {

    @Test
    fun testStrictBypassModeStrategyOverride() {
        BypassConfig.isStrictBypassMode = true
        BypassConfig.isAutoTuning = false
        BypassConfig.applyInternalStrategy(BypassStrategy.DIRECT)

        try {
            // TCP
            val selectedTcp = BypassConfig.getBestStrategyForHost("example.com", TransportType.TCP)
            assertNotEquals(BypassStrategy.DIRECT, selectedTcp)
            assertTrue(StrategyExecutionRegistry.isExecutorSupported(selectedTcp, TransportType.TCP))
            assertEquals(BypassStrategy.SNI_SPLIT, selectedTcp)

            val configTcp = BypassConfig.getSessionConfig("example.com", BypassStrategy.DIRECT, 50L, TransportType.TCP)
            assertNotEquals(BypassStrategy.DIRECT, configTcp.strategy)
            assertTrue(StrategyExecutionRegistry.isExecutorSupported(configTcp.strategy, TransportType.TCP))

            // UDP
            val selectedUdp = BypassConfig.getBestStrategyForHost("example.com", TransportType.UDP)
            assertNotEquals(BypassStrategy.DIRECT, selectedUdp)
            assertTrue(StrategyExecutionRegistry.isExecutorSupported(selectedUdp, TransportType.UDP))
            assertEquals(BypassStrategy.UDP_COMBINED_HYBRID, selectedUdp)

            val configUdp = BypassConfig.getSessionConfig("example.com", BypassStrategy.DIRECT, 50L, TransportType.UDP)
            assertNotEquals(BypassStrategy.DIRECT, configUdp.strategy)
            assertTrue(StrategyExecutionRegistry.isExecutorSupported(configUdp.strategy, TransportType.UDP))

            // DNS
            val selectedDns = BypassConfig.getBestStrategyForHost("example.com", TransportType.DNS)
            assertNotEquals(BypassStrategy.DIRECT, selectedDns)
            assertTrue(StrategyExecutionRegistry.isExecutorSupported(selectedDns, TransportType.DNS))
            assertEquals(BypassStrategy.DNS_OVER_TCP, selectedDns)

            val configDns = BypassConfig.getSessionConfig("example.com", BypassStrategy.DIRECT, 50L, TransportType.DNS)
            assertNotEquals(BypassStrategy.DIRECT, configDns.strategy)
            assertTrue(StrategyExecutionRegistry.isExecutorSupported(configDns.strategy, TransportType.DNS))
        } finally {
            BypassConfig.isStrictBypassMode = false
            BypassConfig.isAutoTuning = true
        }
    }

    @Test
    fun testManualModeIncompatibleStrategySafety() {
        try {
            BypassConfig.isAutoTuning = false
            BypassConfig.setStrategy(BypassStrategy.UDP_COMBINED_NUCLEAR, com.aistudio.pinkproxy.fresh.TransportType.UDP)

            val selectedForTcp = BypassConfig.getBestStrategyForHost("example.com", TransportType.TCP)
            assertTrue(
                "Manual UDP strategy must not be used directly for TCP if unsupported",
                StrategyExecutionRegistry.isExecutorSupported(selectedForTcp, TransportType.TCP)
            )

            val configForTcp = BypassConfig.getSessionConfig("example.com", BypassStrategy.UDP_COMBINED_NUCLEAR, 50L, TransportType.TCP)
            assertTrue(
                "SessionConfig for TCP must produce a valid TCP strategy",
                StrategyExecutionRegistry.isExecutorSupported(configForTcp.strategy, TransportType.TCP)
            )
        } finally {
            BypassConfig.isAutoTuning = true
            BypassConfig.setStrategy(BypassStrategy.SNI_SPLIT, com.aistudio.pinkproxy.fresh.TransportType.TCP)
        }
    }

    @Test
    fun testCustomFragmentationOverride() {
        BypassConfig.frag1 = 12
        BypassConfig.frag2 = 24
        BypassConfig.frag3 = 36

        val config = BypassConfig.getSessionConfig("example.com", BypassStrategy.SNI_TRIPLE, 50L, com.aistudio.pinkproxy.fresh.TransportType.TCP)
        assertEquals(12, config.frag1)
        assertEquals(24, config.frag2)
        assertEquals(36, config.frag3)

        BypassConfig.frag1 = 0
        BypassConfig.frag2 = 0
        BypassConfig.frag3 = 0
    }

    @Test
    fun testSubsystemLifecycleCleanStop() = runTest {
        val testScope = TestScope()
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()

        DeviceMonitor.startDeviceMonitoring(context)
        DeviceMonitor.stopDeviceMonitoring(context)

        CensorshipExpert.start()
        CensorshipExpert.stop()

        PrefetchManager.start(context, null)
        PrefetchManager.stop()

        DnsOptimizer.start(testScope, null)
        DnsOptimizer.stop()

        AutoTtlProber.startProbing(testScope, null)
        AutoTtlProber.stopProbing()

        DnsProtocols.clearPool()
    }
}
