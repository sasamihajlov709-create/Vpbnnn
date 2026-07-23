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
        
        val initialScore = BypassConfig.getScore(BypassStrategy.SNI_SPLIT)
        assertEquals(100, initialScore)
        
        // Record failure
        BypassConfig.recordFailure(BypassStrategy.SNI_SPLIT, true, context)
        val scoreAfterFailure = BypassConfig.getScore(BypassStrategy.SNI_SPLIT)
        assertTrue("Score should decrease after failure", scoreAfterFailure < 100)
        
        // Record success
        BypassConfig.recordSuccess(BypassStrategy.SNI_SPLIT, 50, context)
        val scoreAfterSuccess = BypassConfig.getScore(BypassStrategy.SNI_SPLIT)
        assertTrue("Score should increase after success", scoreAfterSuccess > scoreAfterFailure)
    }

    @Test
    fun testHostMemory() {
        BypassConfig.recordStrategyResult("example.com", BypassStrategy.FAKE_PACKET, true)
        val best = BypassConfig.getBestStrategyForHost("example.com")
        assertEquals(BypassStrategy.FAKE_PACKET, best)
    }
}
