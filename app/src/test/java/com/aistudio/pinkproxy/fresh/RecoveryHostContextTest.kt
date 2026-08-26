package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class RecoveryHostContextTest {

    @Before
    fun setUp() {
        BypassConfig.setPanicMode(false)
        StrategyStateRepository.circuitBreakers.clear()
        StrategyStateRepository.hostStrategyBlacklist.clear()
        BypassConfig.applyInternalStrategy(BypassStrategy.DIRECT)
    }

    @Test
    fun testRecoveryRespectsHostBlacklist() = runTest {
        val host = "youtube.com"
        val transport = TransportType.TCP
        val profileId = NetworkProfileManager.currentProfile.value.id
        
        // 1. Blacklist a specific strategy for this host
        val blacklistedStrategy = BypassStrategy.TCP_SMALL_CHUNKS
        val ctx = CandidateEngine.SelectionContext(transport, profileId, host, HostCategory.STREAMING)
        
        StrategyStateRepository.hostStrategyBlacklist[HostStrategyBlacklistKey(host, transport, profileId, blacklistedStrategy)] = System.currentTimeMillis() + 60000

        // 2. Trigger a stall/failure on this specific host
        RuntimeCoordinator.rotateGlobalStrategy(transport, "Socket Stall Recovery", HostCategory.STREAMING, host = host)
        
        // 3. The newly selected strategy MUST NOT be the blacklisted one for this host.
        // Because rotateGlobalStrategy now correctly passes the `host` parameter to the SelectionContext.
        val newStrategy = BypassConfig.getBestStrategyForHost(host, transport)
        assertNotEquals("Recovery must not select a blacklisted strategy for the specific host", blacklistedStrategy, newStrategy)
    }

    @Test
    fun testCandidateEngineSelectsBestWithContext() = runTest {
        val host = "restricted.com"
        val transport = TransportType.TCP
        val profileId = NetworkProfileManager.currentProfile.value.id
        
        // Populate contextual host memory (this strategy works great for this host)
        val expectedStrategy = BypassStrategy.TLS_SNI_JITTER_SPLIT
        val memory = HostMemory(
            strategy = expectedStrategy,
            transport = transport,
            profileId = profileId,
            successCount = 50, // Massive success count to overwhelm Thompson Sampling randomness
            confidence = 1.0,
            timestamp = System.currentTimeMillis()
        )
        StrategyStateRepository.contextualHostMemory[HostContextKey(host, transport, profileId)] = memory
        
        // Artificially boost the success count massively so it's guaranteed to win
        val state = StrategyStateRepository.getStrategyState(expectedStrategy, transport, HostCategory.OTHER, profileId)
        state.weightedSuccess.addAndGet(500000L) 

        // Penalize all other strategies so they don't get picked by random sampling
        BypassStrategy.entries.forEach {
            if (it != expectedStrategy) {
                val s = StrategyStateRepository.getStrategyState(it, transport, HostCategory.OTHER, profileId)
                s.weightedFailure.addAndGet(50000L)
            }
        }

        // Ask the Engine to select the best for this host
        val ctx = CandidateEngine.SelectionContext(transport, profileId, host, HostCategory.OTHER)
        val best = CandidateEngine.selectBest(ctx)
        
        assertEquals("CandidateEngine should pick the strategy with highest host-specific memory / Bayesian score", expectedStrategy, best)
    }
}
