package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], manifest = Config.NONE)
class TelemetryPreservationTest {

    @Before
    fun setup() {
        BypassConfig.isStrictBypassMode = false
        BypassConfig.isAutoTuning = false
        StrategyStateRepository.clearProfileState("DEFAULT")
    }

    @Test
    fun `test host strategy blacklist is preserved when validStrategies is empty`() {
        val host = "blocked-host.com"
        val transport = TransportType.TCP
        val profileId = "DEFAULT"
        val now = System.currentTimeMillis()

        // Manually blacklist some strategies for this host
        val blKey1 = HostStrategyBlacklistKey(host, transport, profileId, BypassStrategy.SNI_SPLIT)
        val blKey2 = HostStrategyBlacklistKey(host, transport, profileId, BypassStrategy.TLS_SNI_FRAGMENT)

        StrategyStateRepository.hostStrategyBlacklist[blKey1] = now + 100000L
        StrategyStateRepository.hostStrategyBlacklist[blKey2] = now + 100000L

        // To make validStrategies empty, let's just globally circuit breaker all strategies temporarily
        BypassStrategy.entries.forEach { strategy ->
            StrategyStateRepository.circuitBreakers[CircuitBreakerKey(profileId, transport, strategy)] = now + 100000L
        }

        // Run the selector
        // It will fail to find eligible strategies, and fallback to getDefaultFallback
        // It should NOT clear the hostStrategyBlacklist.
        try {
            val strategy = DpiStrategySelector.getBestStrategy(HostCategory.OTHER, host, transport)
        } catch (e: Exception) {
            // expected to throw NoEligibleStrategyException or similar because everything is blocked
        }

        // Verify blacklist was preserved
        assertTrue("Blacklist should be preserved", StrategyStateRepository.hostStrategyBlacklist.containsKey(blKey1))
        assertTrue("Blacklist should be preserved", StrategyStateRepository.hostStrategyBlacklist.containsKey(blKey2))
    }
}
