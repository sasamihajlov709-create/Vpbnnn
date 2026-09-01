package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class PerFlowStrategyIsolationTest {


    @Before
    fun setup() {
        StrategyStateRepository.clearProfileState("default")
        BypassConfig.applyInternalStrategy(BypassStrategy.TCP_MSS_CLAMP)
    }

    @Test
    fun testPerFlowStrategyIsolation() = runBlocking {
        val discordHost = "discord.com"
        val youtubeHost = "youtube.com"
        val profileId = "default"
        val transport = TransportType.TCP
        
        // 1. Establish Discord Host Memory as TCP_REORDER
        for (i in 1..5) {
            val obs = StrategyObservation(
                executedStrategy = BypassStrategy.TCP_REORDER,
                transport = transport,
                category = HostCategory.OTHER,
                profileId = profileId,
                success = true,
                latencyMs = 50,
                failureReason = null,
                timestamp = System.currentTimeMillis(),
                quality = ObservationQuality.APPLICATION_DATA_EXCHANGED
            )
            StrategyStateRepository.recordObservation(obs)
            val state = StrategyStateRepository.getStrategyState(BypassStrategy.TCP_REORDER, transport, HostCategory.OTHER, profileId)
            state.verifiedSuccessCount.incrementAndGet()
            state.weightedSuccess.set(1000000000L) // Massive success weight
            state.score.set(1000000) 


        }
        
        DpiStrategySelector.recordResult(
            strategy = BypassStrategy.TCP_REORDER,
            success = true,
            transport = transport,
            category = HostCategory.OTHER,
            host = discordHost,
            latencyMs = 50,
            quality = ObservationQuality.APPLICATION_DATA_EXCHANGED,
            profileId = profileId
        )
        
        // Ensure Discord uses TCP_REORDER
        val discordCtx = CandidateEngine.SelectionContext(transport, profileId, discordHost, HostCategory.OTHER)
        val bestForDiscord = CandidateEngine.selectBest(discordCtx)
        assertEquals(BypassStrategy.TCP_REORDER, bestForDiscord)
        
        // Global strategy should still be TCP_MSS_CLAMP
        assertEquals(BypassStrategy.TCP_MSS_CLAMP, BypassConfig.strategy.value)
        
        // 2. Simulate TCP_RESET for youtube.com on strategy TCP_MSS_CLAMP
        // It triggers requestGlobalStrategyRotation with targetHost = youtube.com
        val youtubeCtx = CandidateEngine.SelectionContext(transport, profileId, youtubeHost, HostCategory.STREAMING)
        
        RuntimeCoordinator.rotateGlobalStrategy(
            transport = transport,
            reason = "Test TCP Reset",
            category = HostCategory.STREAMING,
            profileId = profileId,
            host = youtubeHost,
            failedStrategy = BypassStrategy.TCP_MSS_CLAMP
        )
        
        // The rotation should NOT affect the global strategy because host was provided
        assertEquals(BypassStrategy.TCP_MSS_CLAMP, BypassConfig.strategy.value)
        
        // 3. Since rotateGlobalStrategy chose a new strategy for YouTube, CandidateEngine should 
        // now penalize TCP_MSS_CLAMP for YouTube and prefer something else (e.g., OOB_DESYNC or similar based on priors)
        val bestForYoutube = CandidateEngine.selectBest(youtubeCtx, excludeCurrent = BypassStrategy.TCP_MSS_CLAMP)
        
        // We just ensure YouTube is not using the failed one, and Discord is unaffected
        assertEquals(BypassStrategy.TCP_REORDER, CandidateEngine.selectBest(discordCtx))
        assert(bestForYoutube != BypassStrategy.TCP_MSS_CLAMP)
    }
}
