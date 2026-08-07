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
}
