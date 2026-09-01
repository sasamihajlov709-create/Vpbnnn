package com.aistudio.pinkproxy.fresh

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class AutoTunerTest {

    @Before
    fun setup() {
        StrategyStateRepository.circuitBreakers.clear()
        StrategyStateRepository.consecutiveFailures.clear()
        StrategyStateRepository.consecutiveFailuresByHost.clear()
        StrategyStateRepository.contextualHostMemory.clear()
        FlowStrategyOverrideStore.clearAll()
    }

    @Test
    fun testPersistenceRegression() {
        val state = StrategyMetricState(
            score = 90,
            successCount = 50,
            failureCount = 10,
            weightedSuccess = 50000L,
            weightedFailure = 20000L,
            verifiedSuccessCount = 30,
            totalLatencyMs = 1500L,
            recentLatencies = listOf(100L, 150L, 120L),
            lastUsedTimestamp = 123456789L
        )

        val json = state.toJsonObject()
        val restored = StrategyMetricState.fromJsonObject(json)

        assertEquals(20000L, restored.weightedFailure)
        assertEquals(50000L, restored.weightedSuccess)
        assertEquals(3, restored.recentLatencies.size)
        assertEquals(150L, restored.recentLatencies[1])
    }

    @Test
    fun testFlowLevelOverrideIsolation() {
        val profileId = "WIFI_TEST"
        val host1 = "youtube.com"
        val host2 = "discord.com"

        // Simulate recovery on youtube.com falling back to TLS_REC_SPLIT
        FlowStrategyOverrideStore.putOverride(
            host = host1,
            transport = TransportType.TCP,
            profileId = profileId,
            strategy = BypassStrategy.TLS_REC_SPLIT,
            reason = "Test Stall"
        )

        // Ensure we retrieve the override for youtube.com
        val overrideYoutube = FlowStrategyOverrideStore.getOverride(host1, TransportType.TCP, profileId)
        assertEquals(BypassStrategy.TLS_REC_SPLIT, overrideYoutube)

        // Ensure discord.com does NOT get the override
        val overrideDiscord = FlowStrategyOverrideStore.getOverride(host2, TransportType.TCP, profileId)
        assertNull(overrideDiscord)
    }
}
