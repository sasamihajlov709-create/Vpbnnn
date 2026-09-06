package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], manifest = Config.NONE)
class PolicyGateSimulatedTest {

    @Test
    fun `test SIMULATED strategy is rejected in normal mode`() {
        val simulatedStrategy = BypassStrategy.UDP_RACING
        
        // Ensure it's simulated
        assertTrue(simulatedStrategy.implementationStatus == ImplementationStatus.SIMULATED)

        val ctx = CandidateEngine.SelectionContext(
            transport = TransportType.UDP,
            profileId = "DEFAULT"
        )
        
        // Should be rejected
        assertFalse(StrategyPolicyGate.isAllowed(simulatedStrategy, ctx))
    }

    @Test
    fun `test SIMULATED strategy is allowed in diagnostic mode`() {
        val simulatedStrategy = BypassStrategy.UDP_RACING

        val ctx = CandidateEngine.SelectionContext(
            transport = TransportType.UDP,
            profileId = "DEFAULT",
            isDiagnosticMode = true
        )
        
        // Should be allowed in diagnostic mode
        assertTrue(StrategyPolicyGate.isAllowed(simulatedStrategy, ctx))
    }
}
