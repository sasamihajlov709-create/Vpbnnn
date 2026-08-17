package com.aistudio.pinkproxy.fresh

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class AutoTunerTournamentSelectionTest {

    @Before
    fun setup() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        BypassConfig.clearScores(context)
        DpiEngine.resetStrategyScoresForNetworkChange()
    }

    @Test
    fun testTournamentSelectionPicksHighQualityCandidate() {
        val host = "video.youtube.com"
        val category = HostCategory.STREAMING
        val transport = TransportType.TCP

        // Train a specific strategy to be highly successful
        val winningStrat = BypassStrategy.SNI_SPLIT
        for (i in 0 until 5) {
            DpiStrategySelector.recordResult(
                strategy = winningStrat,
                success = true,
                category = category,
                latencyMs = 25L,
                host = host,
                quality = ObservationQuality.FULL_DATA_TRANSFER,
                transport = transport
            )
        }

        // Selected strategy should rapidly converge to winning candidate or high confidence equivalent
        val chosen = DpiStrategySelector.getBestStrategy(category, host, transport)
        assertNotNull(chosen)
        assertEquals(winningStrat, chosen)
    }

    @Test
    fun testTournamentRespectsBlacklistAndRecoversToDiverseFallback() {
        val host = "discord.gg"
        val category = HostCategory.MESSENGER
        val transport = TransportType.TCP
        val failingStrat = BypassStrategy.SNI_SPLIT

        // Record multiple severe failures (TCP_RESET)
        for (i in 0 until 3) {
            DpiStrategySelector.recordResult(
                strategy = failingStrat,
                success = false,
                category = category,
                reason = FailureReason.TCP_RESET,
                host = host,
                quality = ObservationQuality.CONNECT_ONLY,
                transport = transport
            )
        }

        // Failing strategy must be blacklisted for this host
        val isBlacklisted = DpiEngine.isBlacklisted(failingStrat, host)
        assertTrue("Strategy should be blacklisted after consecutive TCP resets", isBlacklisted)

        // Selection should automatically pivot away from blacklisted strategy
        val selected = DpiStrategySelector.getBestStrategy(category, host, transport)
        assertNotEquals(failingStrat, selected)
        assertTrue("Selected strategy must be compatible with TCP", DpiStrategySelector.isFamilyCompatible(selected.family, transport))
    }
}
