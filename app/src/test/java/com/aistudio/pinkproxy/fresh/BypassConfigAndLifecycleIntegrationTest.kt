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
        BypassConfig.setStrategy(BypassStrategy.DIRECT)

        try {
            val selected = BypassConfig.getBestStrategyForHost("example.com")
            assertNotEquals(BypassStrategy.DIRECT, selected)
            assertEquals(BypassStrategy.SNI_SPLIT, selected)

            val config = BypassConfig.getSessionConfig("example.com", BypassStrategy.DIRECT, 50L)
            assertNotEquals(BypassStrategy.DIRECT, config.strategy)
            assertEquals(BypassStrategy.SNI_SPLIT, config.strategy)
        } finally {
            BypassConfig.isStrictBypassMode = false
            BypassConfig.isAutoTuning = true
        }
    }

    @Test
    fun testCustomFragmentationOverride() {
        BypassConfig.frag1 = 12
        BypassConfig.frag2 = 24
        BypassConfig.frag3 = 36

        val config = BypassConfig.getSessionConfig("example.com", BypassStrategy.SNI_TRIPLE, 50L)
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
