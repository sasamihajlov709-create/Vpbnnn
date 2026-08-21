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
            DpiStrategySelector.recordResult(
                strategy = BypassStrategy.TLS_APP_DATA_SPLIT,
                success = true,
                transport = TransportType.TCP,
                quality = ObservationQuality.APPLICATION_DATA_EXCHANGED,
                category = HostCategory.MESSENGER,
                latencyMs = 20
            )
        }
        repeat(5) {
            DpiStrategySelector.recordResult(
                strategy = BypassStrategy.SNI_SPLIT,
                success = false,
                transport = TransportType.TCP,
                quality = ObservationQuality.CONNECT_ONLY,
                category = HostCategory.MESSENGER
            )
        }

        val appDataScore = DpiStrategySelector.getAverageScore(BypassStrategy.TLS_APP_DATA_SPLIT)
        val sniSplitScore = DpiStrategySelector.getAverageScore(BypassStrategy.SNI_SPLIT)
        val best = DpiStrategySelector.getBestStrategy(HostCategory.MESSENGER)
        assertTrue("TLS_APP_DATA_SPLIT should score higher than failing SNI_SPLIT", appDataScore > sniSplitScore)
        assertTrue("Selected strategy should not be the failing SNI_SPLIT", best != BypassStrategy.SNI_SPLIT)
    }

    @Test
    fun testDpiStoragePersistence() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        BypassConfig.clearScores(context)

        repeat(3) {
            DpiEngine.recordStrategyResult(
                host = "testdomain.org",
                strat = BypassStrategy.SNI_SPLIT,
                success = true,
                transport = TransportType.TCP,
                quality = ObservationQuality.APPLICATION_DATA_EXCHANGED,
                latencyMs = 30
            )
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

        DpiEngine.recordStrategyResult(
            host = "netdomain.com",
            strat = BypassStrategy.SNI_SPLIT,
            success = false,
            transport = TransportType.TCP,
            quality = ObservationQuality.CONNECT_ONLY
        )
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
            DpiStrategySelector.recordResult(
                strategy = BypassStrategy.TCP_COMBINED_HYBRID,
                success = true,
                transport = TransportType.TCP,
                quality = ObservationQuality.APPLICATION_DATA_EXCHANGED,
                category = HostCategory.STREAMING,
                latencyMs = 25
            )
        }
        val wifiScore = DpiStrategySelector.getAverageScore(BypassStrategy.TCP_COMBINED_HYBRID).toInt()
        assertTrue("Wi-Fi learned score should be elevated", wifiScore > 100)

        // Switch to Cellular: Wi-Fi scores saved, Cellular loaded (fresh/default)
        DpiEngine.switchNetworkProfile(wifiProfile, cellProfile, context)
        val initialCellScore = DpiStrategySelector.getAverageScore(BypassStrategy.TCP_COMBINED_HYBRID).toInt()
        assertEquals("New Cellular profile should start at default baseline score", 100, initialCellScore)

        // Learn different strategy on Cellular
        repeat(4) {
            DpiStrategySelector.recordResult(
                strategy = BypassStrategy.SNI_SPLIT,
                success = true,
                transport = TransportType.TCP,
                quality = ObservationQuality.APPLICATION_DATA_EXCHANGED,
                category = HostCategory.STREAMING,
                latencyMs = 15
            )
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

        // 1st success (HANDSHAKE_COMPLETE qualifies for host memory)
        DpiStrategySelector.recordResult(
            strategy = BypassStrategy.TLS_SNI_JITTER_SPLIT,
            success = true,
            transport = TransportType.TCP,
            category = HostCategory.AI,
            latencyMs = 50,
            host = testHost,
            quality = ObservationQuality.HANDSHAKE_COMPLETE
        )
        val mem1 = DpiEngine.hostSpecificMemory[testHost]
        assertNotNull(mem1)
        assertEquals(1, mem1?.successCount)

        // 2nd success
        DpiStrategySelector.recordResult(
            strategy = BypassStrategy.TLS_SNI_JITTER_SPLIT,
            success = true,
            transport = TransportType.TCP,
            category = HostCategory.AI,
            latencyMs = 45,
            host = testHost,
            quality = ObservationQuality.APPLICATION_DATA_EXCHANGED
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

    @Test
    fun testStrategySubstitutionTrackingAndPenalty() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        BypassConfig.clearScores(context)
        DpiEngine.resetStrategyScoresForNetworkChange()

        val testHost = "substituted-target.org"
        val requested = BypassStrategy.TCP_MSS_CLAMP
        val executed = BypassStrategy.SNI_SPLIT

        // Test failed execution with substitution
        DpiStrategySelector.recordResult(
            strategy = executed,
            success = false,
            transport = TransportType.TCP,
            quality = ObservationQuality.CONNECT_ONLY,
            category = HostCategory.OTHER,
            reason = FailureReason.TIMEOUT,
            host = testHost,
            requestedStrategy = requested,
            effectiveStrategy = requested
        )

        // Requested strategy should have received substitution penalty
        val penalty = DpiEngine.globalPenalties[requested]?.get() ?: 0
        assertTrue("Requested strategy should receive penalty on failure", penalty > 0)

        // Executed strategy should have recorded failure
        val failCount = DpiEngine.failureHistory[executed]?.get() ?: 0
        assertEquals(1, failCount)

        // Test successful execution with substitution
        DpiStrategySelector.recordResult(
            strategy = executed,
            success = true,
            transport = TransportType.TCP,
            quality = ObservationQuality.APPLICATION_DATA_EXCHANGED,
            category = HostCategory.OTHER,
            latencyMs = 50,
            host = testHost,
            requestedStrategy = requested,
            effectiveStrategy = requested
        )

        val successCount = DpiEngine.successHistory[executed]?.get() ?: 0
        assertEquals(1, successCount)
    }
}
