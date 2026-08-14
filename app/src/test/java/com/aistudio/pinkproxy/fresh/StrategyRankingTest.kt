package com.aistudio.pinkproxy.fresh

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
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

    @Test
    fun testMultiNetworkProfileIsolation() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        BypassConfig.clearScores(context)

        val wifiProfile = NetworkProfile(
            id = "wifi_test_network",
            type = NetworkType.WIFI,
            displayName = "Test Wi-Fi",
            timestamp = System.currentTimeMillis()
        )
        val cellProfile = NetworkProfile(
            id = "cell_test_network",
            type = NetworkType.MOBILE,
            displayName = "Test Cellular",
            timestamp = System.currentTimeMillis()
        )

        // Learn strategy on Wi-Fi
        DpiEngine.resetStrategyScoresForNetworkChange()
        repeat(4) {
            DpiStrategySelector.recordResult(BypassStrategy.TCP_COMBINED_HYBRID, true, HostCategory.STREAMING, latencyMs = 25)
        }
        val wifiScore = DpiStrategySelector.getAverageScore(BypassStrategy.TCP_COMBINED_HYBRID).toInt()
        assertTrue("Wi-Fi learned score should be elevated", wifiScore > 100)

        // Switch to Cellular: Wi-Fi scores saved, Cellular loaded (fresh/default)
        DpiEngine.switchNetworkProfile(wifiProfile, cellProfile, context)
        val initialCellScore = DpiStrategySelector.getAverageScore(BypassStrategy.TCP_COMBINED_HYBRID).toInt()
        assertEquals("New Cellular profile should start at default baseline score", 100, initialCellScore)

        // Learn different strategy on Cellular
        repeat(4) {
            DpiStrategySelector.recordResult(BypassStrategy.SNI_SPLIT, true, HostCategory.STREAMING, latencyMs = 15)
        }
        val cellSniScore = DpiStrategySelector.getAverageScore(BypassStrategy.SNI_SPLIT).toInt()
        assertTrue("Cellular learned score for SNI_SPLIT should be elevated", cellSniScore > 100)

        // Switch back to Wi-Fi: cellular saved, Wi-Fi restored
        DpiEngine.switchNetworkProfile(cellProfile, wifiProfile, context)
        val restoredWifiScore = DpiStrategySelector.getAverageScore(BypassStrategy.TCP_COMBINED_HYBRID).toInt()
        assertEquals("Wi-Fi score should be perfectly restored", wifiScore, restoredWifiScore)
    }

    @Test
    fun testHostSpecificMemoryMultiSessionConfidence() {
        val testHost = "secure.api.service"
        DpiEngine.consecutiveFailuresByHost.clear()
        DpiEngine.hostSpecificMemory.clear()

        // 1st success
        DpiStrategySelector.recordResult(
            BypassStrategy.TLS_SNI_JITTER_SPLIT,
            true,
            HostCategory.AI,
            latencyMs = 50,
            host = testHost,
            quality = ObservationQuality.TLS_RECORD_RECEIVED
        )
        val mem1 = DpiEngine.hostSpecificMemory[testHost]
        assertNotNull(mem1)
        assertEquals(1, mem1?.successCount)

        // 2nd success
        DpiStrategySelector.recordResult(
            BypassStrategy.TLS_SNI_JITTER_SPLIT,
            true,
            HostCategory.AI,
            latencyMs = 45,
            host = testHost,
            quality = ObservationQuality.FULL_DATA_TRANSFER
        )
        val mem2 = DpiEngine.hostSpecificMemory[testHost]
        assertNotNull(mem2)
        assertEquals(2, mem2?.successCount)

        // Best strategy query should pick the verified strategy
        val best = DpiStrategySelector.getBestStrategy(HostCategory.AI, host = testHost, transport = TransportType.TCP)
        assertEquals(BypassStrategy.TLS_SNI_JITTER_SPLIT, best)
    }

    @Test
    fun testAnalyzeAndAdjustDoesNotDistortBaselineScores() {
        DpiEngine.resetStrategyScoresForNetworkChange()
        val initialAvg = DpiStrategySelector.getAverageScore(BypassStrategy.SNI_SPLIT)
        assertEquals(100.0, initialAvg, 0.01)

        // Run analyzer adjustment
        DpiAnalyzer.analyzeAndAdjust()

        val afterAvg = DpiStrategySelector.getAverageScore(BypassStrategy.SNI_SPLIT)
        assertEquals(100.0, afterAvg, 1.0)
    }
}
