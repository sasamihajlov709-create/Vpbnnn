package com.aistudio.pinkproxy.fresh

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class StrategyRankingTest {
    @Test
    fun testStrategyScoring() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        
        // Reset scores
        BypassConfig.clearScores(context)
        
        val initialScore = DpiStrategySelector.getAverageScore(BypassStrategy.SNI_SPLIT).toInt()
        println("initialScore: $initialScore")
        assertEquals(100, initialScore)
        
        // Record failure
        BypassConfig.recordFailure(BypassStrategy.SNI_SPLIT, "example.com")
        val scoreAfterFailure = DpiStrategySelector.getAverageScore(BypassStrategy.SNI_SPLIT).toInt()
        println("scoreAfterFailure: $scoreAfterFailure")
        assertTrue("Score should decrease after failure", scoreAfterFailure < 100)
        
        // Record success
        BypassConfig.recordSuccess(BypassStrategy.SNI_SPLIT, 50, "example.com")
        val scoreAfterSuccess = DpiStrategySelector.getAverageScore(BypassStrategy.SNI_SPLIT).toInt()
        println("scoreAfterSuccess: $scoreAfterSuccess")
        assertTrue("Score should increase after success", scoreAfterSuccess > scoreAfterFailure)
    }

    @Test
    fun testHostMemory() {
        BypassConfig.isAutoTuning = true
        BypassConfig.recordSuccess(BypassStrategy.FAKE_PACKET, 100, "example.com")
        val best = BypassConfig.getBestStrategyForHost("example.com")
        println("DEBUG: best strategy for example.com is $best")
        assertEquals(BypassStrategy.FAKE_PACKET, best)
    }

    @Test
    fun testTopCandidateSelection() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        BypassConfig.clearScores(context)

        repeat(5) {
            DpiStrategySelector.recordResult(BypassStrategy.TLS_APP_DATA_SPLIT, true, HostCategory.MESSENGER, latencyMs = 20)
        }
        repeat(5) {
            DpiStrategySelector.recordResult(BypassStrategy.SNI_SPLIT, false, HostCategory.MESSENGER)
        }

        val best = DpiStrategySelector.getBestStrategy(HostCategory.MESSENGER)
        assertTrue("Selected strategy should be high scoring", best == BypassStrategy.TLS_APP_DATA_SPLIT || best.group != StrategyGroup.LIGHT)
    }

    @Test
    fun testDpiStoragePersistence() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        BypassConfig.clearScores(context)

        repeat(3) {
            DpiEngine.recordStrategyResult("testdomain.org", BypassStrategy.SNI_SPLIT, true, 30)
        }
        val scoreBeforeSave = DpiStrategySelector.getAverageScore(BypassStrategy.SNI_SPLIT).toInt()

        DpiStorage.saveScores(context)
        DpiEngine.resetStrategyScoresForNetworkChange()
        DpiStorage.loadScores(context)

        val scoreAfterLoad = DpiStrategySelector.getAverageScore(BypassStrategy.SNI_SPLIT).toInt()
        assertEquals("Loaded score should match saved score", scoreBeforeSave, scoreAfterLoad)
    }

    @Test
    fun testNetworkChangeReset() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        BypassConfig.clearScores(context)

        DpiEngine.recordStrategyResult("netdomain.com", BypassStrategy.SNI_SPLIT, false)
        assertTrue(DpiStrategySelector.getAverageScore(BypassStrategy.SNI_SPLIT) < 100)

        DpiEngine.resetStrategyScoresForNetworkChange()

        assertEquals(100, DpiStrategySelector.getAverageScore(BypassStrategy.SNI_SPLIT).toInt())
        assertTrue(DpiEngine.successHistory.isEmpty())
        assertTrue(DpiEngine.failureHistory.isEmpty())
    }
}
