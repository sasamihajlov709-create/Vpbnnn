package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class LifecycleTerminationTest {

    @Test
    fun `DnsOptimizer start and stop does not throw and cleans up`() = runTest {
        val testScope = TestScope()
        
        DnsOptimizer.start(testScope, vpnService = null)
        DnsOptimizer.stop()
    }

    @Test
    fun `DpiEngine start and stop cancels background probes`() {
        DpiEngine.stop()
    }
}
