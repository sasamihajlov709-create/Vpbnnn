package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], manifest = Config.NONE)
class CandidateEngineIntegrationTest {

    @Before
    fun setup() {
        BypassConfig.isStrictBypassMode = false
        BypassConfig.isAutoTuning = false
        BypassConfig.autoTuningMode = AutoTuningMode.EXPLORATION
        StrategyStateRepository.clearProfileState(NetworkProfileManager.currentProfile.value.id)
        StrategyStateRepository.clearProfileState("DEFAULT")
    }

    @Test
    fun `test CandidateEngine filters blacklisted strategies unless diagnostic mode`() {
        val strategy = BypassStrategy.SNI_SPLIT
        val host = "blocked-host.com"
        val ctx = CandidateEngine.SelectionContext(
            host = host,
            transport = TransportType.TCP,
            profileId = "DEFAULT"
        )
        
        // Block the strategy for this host
        val blKey = HostStrategyBlacklistKey(host, TransportType.TCP, "DEFAULT", strategy)
        StrategyStateRepository.hostStrategyBlacklist[blKey] = System.currentTimeMillis() + 10000

        // Normal mode should block it
        assertFalse(StrategyPolicyGate.isAllowed(strategy, ctx))

        // ignoreHostBlacklist mode should allow it
        val diagCtx = ctx.copy(ignoreHostBlacklist = true)
        assertTrue(StrategyPolicyGate.isAllowed(strategy, diagCtx))
    }

    @Test
    fun `test StrategyPolicyGate resolveNextEscalation throws NoEligibleStrategyException`() {
        val host = "strict-host.com"
        val ctx = CandidateEngine.SelectionContext(
            host = host,
            transport = TransportType.TCP,
            profileId = "DEFAULT"
        )

        // Exhaust all TCP strategies by putting them in attempted strategies
        val allStrategies = BypassStrategy.entries.filter { 
            DpiStrategySelector.isFamilyCompatible(it.family, TransportType.TCP) &&
            CapabilityMatrix.isExecutorSupported(it, TransportType.TCP)
        }.toSet()

        assertThrows(NoEligibleStrategyException::class.java) {
            StrategyPolicyGate.resolveNextEscalation(
                failedStrategy = BypassStrategy.SNI_SPLIT,
                reason = FailureReason.TCP_RESET,
                context = ctx,
                attemptedStrategies = allStrategies
            )
        }
    }

    @Test
    fun `test BypassConfig getFallbackStrategy in Strict Mode propagates NoEligibleStrategyException`() {
        BypassConfig.isStrictBypassMode = true
        val host = "strict-mode-host.com"

        // Exhaust all TCP strategies
        val allStrategies = BypassStrategy.entries.toSet()

        // We can't easily mock the 'attemptedStrategies' list since it's internal to getFallbackStrategy
        // But we can block all of them using global circuit breakers which are not bypassed by diagnostic mode
        allStrategies.forEach { strategy ->
            val cbKey = CircuitBreakerKey(NetworkProfileManager.currentProfile.value.id, TransportType.TCP, strategy)
            StrategyStateRepository.circuitBreakers[cbKey] = System.currentTimeMillis() + 10000
        }

        assertThrows(NoEligibleStrategyException::class.java) {
            BypassConfig.getFallbackStrategy(
                current = BypassStrategy.SNI_SPLIT,
                transport = TransportType.TCP,
                reason = FailureReason.TCP_RESET,
                host = host,
                category = HostCategory.OTHER
            )
        }
    }
}
