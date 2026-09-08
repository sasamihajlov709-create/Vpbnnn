package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.junit.Before

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], manifest = Config.NONE)
class ExtremeFallbackRegressionTest {

    @Before
    fun setup() {
        BypassConfig.isStrictBypassMode = false
    }

    @Test
    fun `test extreme fallback never returns SIMULATED strategy`() {
        // We know UDP_RACING is SIMULATED and EXTREME group
        val simulatedExtreme = BypassStrategy.UDP_RACING
        assert(simulatedExtreme.implementationStatus == ImplementationStatus.SIMULATED)
        assert(simulatedExtreme.group == StrategyGroup.EXTREME)

        val result = DpiStrategySelector.getBestExtremeStrategy(
            transport = TransportType.UDP,
            host = "test.com"
        )
        
        assertNotEquals(simulatedExtreme, result)
        
        val fallback = DpiStrategySelector.getDefaultExtremeFallback(
            transport = TransportType.UDP,
            context = CandidateEngine.SelectionContext(TransportType.UDP)
        )
        assertNotEquals(simulatedExtreme, fallback)
    }
}
