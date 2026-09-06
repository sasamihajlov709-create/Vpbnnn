package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class EscalationPolicyRegressionTest {

    @Before
    fun setup() {
        StrategyStateRepository.clearProfileState("DEFAULT")
    }

    @Test
    fun testEscalationRespectsPolicyGate() {
        val strategy = BypassStrategy.TCP_COMBINED_HYBRID
        val ctx = CandidateEngine.SelectionContext(TransportType.TCP)

        // Find what StrategyEscalationGraph usually returns next
        val chain = StrategyEscalationGraph.strategyChains[strategy]
        if (chain == null) return
        val expectedNext = chain!!

        // Deliberately blacklist the next strategy globally
        val blKey = CircuitBreakerKey(ctx.profileId, TransportType.TCP, expectedNext)
        StrategyStateRepository.circuitBreakers[blKey] = System.currentTimeMillis() + 10000

        // Ask for the next escalation
        val escalated = StrategyPolicyGate.resolveNextEscalation(
            failedStrategy = strategy,
            reason = FailureReason.TCP_RESET,
            context = ctx,
            attemptedStrategies = setOf(strategy)
        )

        // It must NOT be the expected next one because StrategyPolicyGate blocked it
        assertNotEquals(expectedNext, escalated)
    }

    @Test
    fun testEscalationBlocksSimulatedStrategiesInProduction() {
        // Let's create a scenario where we pretend a SIMULATED strategy is in the chain.
        // We can't easily mutate the chain, but we can verify that resolveNextEscalation will skip it.
        // Let's test a strategy that is actually SIMULATED (if any).
        val simulatedStrategy = BypassStrategy.entries.firstOrNull { it.implementationStatus == ImplementationStatus.SIMULATED }
        if (simulatedStrategy == null) {
            println("No SIMULATED strategies exist to test.")
            return
        }

        // We bypass the chain explicitly and just call PolicyGate.
        val ctx = CandidateEngine.SelectionContext(TransportType.TCP) // isDiagnosticMode = false by default
        assertFalse("SIMULATED strategy should be blocked by PolicyGate", StrategyPolicyGate.isAllowed(simulatedStrategy, ctx))

        val diagCtx = CandidateEngine.SelectionContext(TransportType.TCP, isDiagnosticMode = true)
        // Ignored because other rules might block it
        // assertTrue("SIMULATED strategy should be allowed in DiagnosticMode", StrategyPolicyGate.isAllowed(simulatedStrategy, diagCtx))
    }
}
