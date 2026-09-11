package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], manifest = Config.NONE)
class CandidateEngineTest {

    @Before
    fun setup() {
        BypassConfig.autoTuningMode = AutoTuningMode.EXPLORATION
        StrategyStateRepository.clearProfileState("DEFAULT")
        StrategyStateRepository.contextualHostMemory.clear()
        StrategyStateRepository.consecutiveFailuresByHost.clear()
    }

    @Test
    fun `test Bayesian ranking favors high success strategies`() {
        val strategyGood = BypassStrategy.SNI_SPLIT
        val strategyBad = BypassStrategy.TCP_REVERSE_FRAG
        
        val ctx = CandidateEngine.SelectionContext(
            transport = TransportType.TCP,
            profileId = "DEFAULT",
            host = "test.com",
            category = HostCategory.OTHER
        )

        // Seed some successes for Good Strategy
        val goodState = StrategyStateRepository.getStrategyState(strategyGood, TransportType.TCP, HostCategory.OTHER, "DEFAULT")
        goodState.recordObservation(StrategyObservation(
            executedStrategy = strategyGood,
            transport = TransportType.TCP,
            profileId = "DEFAULT",
            success = true,
            quality = ObservationQuality.APPLICATION_DATA_EXCHANGED
        ))

        // Seed some failures for Bad Strategy
        val badState = StrategyStateRepository.getStrategyState(strategyBad, TransportType.TCP, HostCategory.OTHER, "DEFAULT")
        badState.recordObservation(StrategyObservation(
            executedStrategy = strategyBad,
            transport = TransportType.TCP,
            profileId = "DEFAULT",
            success = false,
            failureReason = FailureReason.TCP_RESET,
            quality = ObservationQuality.CONNECT_ONLY
        ))

val candidates = listOf(strategyGood, strategyBad)
        var goodWins = 0
        val runs = 1000
        for (i in 0 until runs) {
            val ranked = CandidateEngine.rankCandidatesBayesian(candidates, ctx)
            if (ranked.first() == strategyGood) {
                goodWins++
            }
        }
        
        assertTrue("Good strategy should win significantly more often (won $goodWins/$runs)", goodWins > 900)
    }

    @Test
    fun `test host memory bonus influences ranking`() {
        val strategyMem = BypassStrategy.HTTP_LINE_SPLIT
        val host = "memory-host.com"
        val ctx = CandidateEngine.SelectionContext(
            transport = TransportType.TCP,
            profileId = "DEFAULT",
            host = host,
            category = HostCategory.OTHER
        )

        // Add to host memory
        val key = HostContextKey(host, TransportType.TCP, "DEFAULT")
        StrategyStateRepository.contextualHostMemory[key] = HostMemory(
            strategy = strategyMem,
            timestamp = System.currentTimeMillis(),
            successCount = 5,
            transport = TransportType.TCP,
            profileId = "DEFAULT"
        )

        val candidates = BypassStrategy.entries.toList()
        val ranked = CandidateEngine.rankCandidatesBayesian(candidates, ctx)
        
        // Due to the host memory bonus (+150 * confidence), it should absolutely rank #1
        assertEquals(strategyMem, ranked.first())
    }
}
