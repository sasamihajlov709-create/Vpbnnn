package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertNotEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.junit.Before

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], manifest = Config.NONE)
class RuntimeCoordinatorPolicyTest {

    @Before
    fun setup() {
        BypassConfig.isStrictBypassMode = false
    }

    @Test
    fun `test rotateGlobalStrategy never returns SIMULATED strategy`() = runTest {
        val simulatedStrategy = BypassStrategy.UDP_RACING
        
        // Force candidate engine to think UDP_RACING is awesome
        // (Even if it thinks so, PolicyGate should reject it)
        val ctxKey = HostContextKey("test.com", TransportType.UDP, "DEFAULT")
        StrategyStateRepository.contextualHostMemory[ctxKey] = HostMemory(
            strategy = simulatedStrategy,
            timestamp = System.currentTimeMillis(),
            successCount = 10,
            transport = TransportType.UDP,
            profileId = "DEFAULT",
            confidence = 1.0
        )
        
        val result = RuntimeCoordinator.rotateGlobalStrategy(
            transport = TransportType.UDP,
            reason = "Test Rotation",
            host = "test.com"
        )
        
        assertNotEquals(simulatedStrategy, result)
    }
}
