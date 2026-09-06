package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class FallbackPolicyRegressionTest {

    @Before
    fun setup() {
        StrategyStateRepository.clearProfileState("DEFAULT")
        BypassConfig.isStrictBypassMode = false
    }

    @Test
    fun testFallbackDoesNotBypassStrictBypassMode() {
        BypassConfig.isStrictBypassMode = true
        val ctx = CandidateEngine.SelectionContext(TransportType.TCP)

        // Strict Bypass mode blocks BypassStrategy.DIRECT. Let's make sure the fallback generator doesn't violate it.
        try {
            val strategy = DpiStrategySelector.getDefaultFallback(TransportType.TCP, ctx)
            assertNotEquals(BypassStrategy.DIRECT, strategy)
        } catch (e: NoEligibleStrategyException) {
            // Throwing is also an acceptable behavior if no other strategies are allowed
            assertTrue(true)
        }
    }

    @Test
    fun testFallbackPropagatesContextProperly() {
        val host = "blocked-host.example.com"
        val ctx = CandidateEngine.SelectionContext(TransportType.TCP, host = host)

        // Block all standard fallback strategies for this specific host
        val blKey1 = HostStrategyBlacklistKey(host, TransportType.TCP, ctx.profileId, BypassStrategy.SNI_SPLIT)
        val blKey2 = HostStrategyBlacklistKey(host, TransportType.TCP, ctx.profileId, BypassStrategy.TLS_SNI_EXT_MANGLE)
        StrategyStateRepository.hostStrategyBlacklist[blKey1] = System.currentTimeMillis() + 10000
        StrategyStateRepository.hostStrategyBlacklist[blKey2] = System.currentTimeMillis() + 10000

        try {
            val fallback = DpiStrategySelector.getDefaultFallback(TransportType.TCP, ctx)
            // It should NOT be the blacklisted strategies because the context (host) must be propagated down to the policy check
            assertNotEquals(BypassStrategy.SNI_SPLIT, fallback)
            assertNotEquals(BypassStrategy.TLS_SNI_EXT_MANGLE, fallback)
        } catch (e: NoEligibleStrategyException) {
            // Expected if nothing else is left
        }
    }
}
