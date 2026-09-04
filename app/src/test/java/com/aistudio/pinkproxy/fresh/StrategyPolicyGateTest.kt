package com.aistudio.pinkproxy.fresh

import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], manifest = Config.NONE)
class StrategyPolicyGateTest {

    @Before
    fun setup() {
        BypassConfig.isStrictBypassMode = false
        BypassConfig.isAutoTuning = false
        BypassConfig.autoTuningMode = AutoTuningMode.EXPLORATION
    }

    @After
    fun tearDown() {
        BypassConfig.isStrictBypassMode = false
        BypassConfig.isAutoTuning = true
        BypassConfig.autoTuningMode = AutoTuningMode.EXPLORATION
    }

    @Test
    fun testStableModeBlocksUnverifiedStrategyAcrossAllGateways() {
        BypassConfig.isAutoTuning = true
        BypassConfig.autoTuningMode = AutoTuningMode.STABLE

        val context = CandidateEngine.SelectionContext(
            transport = TransportType.TCP,
            host = "blocked-target.com"
        )

        // Find an unverified but supported strategy (e.g. SNI_TRIPLE or similar UNVERIFIED)
        val unverifiedStrategy = BypassStrategy.entries.firstOrNull {
            it.validationStatus == ValidationStatus.UNVERIFIED &&
            StrategyExecutionRegistry.isExecutorSupported(it, TransportType.TCP) &&
            DpiStrategySelector.isFamilyCompatible(it.family, TransportType.TCP)
        }

        if (unverifiedStrategy != null) {
            // 1. Direct StrategyPolicyGate check
            assertFalse(
                "UNVERIFIED strategy must NOT be allowed in STABLE mode",
                StrategyPolicyGate.isAllowed(unverifiedStrategy, context)
            )

            // 2. resolveOrFallback in STABLE mode must divert to verified alternative
            val resolved = StrategyPolicyGate.resolveOrFallback(unverifiedStrategy, context)
            assertNotEquals(unverifiedStrategy, resolved)
            assertTrue(StrategyPolicyGate.isAllowed(resolved, context))

            // 3. BypassConfig.getSessionConfig must NOT return unverifiedStrategy in STABLE mode
            val sessionConfig = BypassConfig.getSessionConfig("blocked-target.com", unverifiedStrategy, 50L, TransportType.TCP)
            assertNotEquals(
                "getSessionConfig must strictly enforce STABLE gatekeeper",
                unverifiedStrategy,
                sessionConfig.strategy
            )
        }
    }

    @Test
    fun testStrictModeStrictlyDisallowsDirect() {
        BypassConfig.isStrictBypassMode = true
        val context = CandidateEngine.SelectionContext(TransportType.TCP)

        assertFalse(StrategyPolicyGate.isAllowed(BypassStrategy.DIRECT, context))

        val resolved = StrategyPolicyGate.resolveOrFallback(BypassStrategy.DIRECT, context)
        assertNotEquals(BypassStrategy.DIRECT, resolved)
        assertEquals(BypassStrategy.SNI_SPLIT, resolved)

        val sessionConfig = BypassConfig.getSessionConfig("test.org", BypassStrategy.DIRECT, 0L, TransportType.TCP)
        assertNotEquals(BypassStrategy.DIRECT, sessionConfig.strategy)
    }

    @Test
    fun testIncompatibleTransportRejection() {
        val tcpContext = CandidateEngine.SelectionContext(TransportType.TCP)
        // UDP strategy given to TCP transport
        val udpStrategy = BypassStrategy.UDP_COMBINED_NUCLEAR

        assertFalse(
            "UDP nuclear strategy must be rejected for TCP transport",
            StrategyPolicyGate.isAllowed(udpStrategy, tcpContext)
        )

        val resolved = StrategyPolicyGate.resolveOrFallback(udpStrategy, tcpContext)
        assertTrue(
            "Resolved fallback must be valid for TCP",
            DpiStrategySelector.isFamilyCompatible(resolved.family, TransportType.TCP)
        )
    }

    @Test
    fun testStrictModeNeverReturnsUnverifiedFallbackWhenNoEligibleCandidates() {
        BypassConfig.isStrictBypassMode = true
        BypassConfig.isAutoTuning = true
        BypassConfig.autoTuningMode = AutoTuningMode.STABLE
        
        val context = CandidateEngine.SelectionContext(
            transport = TransportType.TCP,
            host = "super-blocked-target.com"
        )
        
        BypassStrategy.entries.forEach {
            val cbKey = CircuitBreakerKey(context.profileId, context.transport, it)
            StrategyStateRepository.circuitBreakers[cbKey] = System.currentTimeMillis() + 100000L
        }

        try {
            StrategyPolicyGate.resolveOrFallback(BypassStrategy.DIRECT, context)
            fail("Should have thrown NoEligibleStrategyException when no eligible candidates exist in strict mode")
        } catch (e: NoEligibleStrategyException) {
            // Success
        } finally {
            StrategyStateRepository.circuitBreakers.clear()
        }
    }
}
