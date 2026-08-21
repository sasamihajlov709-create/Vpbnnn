package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

class StrategyStateRepositoryPersistenceTest {

    @Before
    fun setUp() {
        StrategyStateRepository.resetAll()
    }

    @Test
    fun testRepositoryStateRestoreAndBayesianIntegration() {
        val testProfile = "lte-test-profile"
        val testKey = StrategyContextKey(
            strategy = BypassStrategy.TLS_REC_SPLIT,
            transport = TransportType.TCP,
            category = HostCategory.STREAMING,
            profileId = testProfile
        )

        // Seed metric
        val metric = StrategyMetricState(
            score = 250,
            successCount = 20,
            failureCount = 2,
            weightedSuccess = 18500L
        )

        StrategyStateRepository.restoreStates(mapOf(testKey to metric))

        val restoredState = StrategyStateRepository.getStrategyState(
            strategy = BypassStrategy.TLS_REC_SPLIT,
            transport = TransportType.TCP,
            category = HostCategory.STREAMING,
            profileId = testProfile
        )

        assertEquals(250, restoredState.score.get())
        assertEquals(20, restoredState.successCount.get())
        assertEquals(2, restoredState.failureCount.get())
        assertEquals(18500L, restoredState.weightedSuccess.get())
        assertEquals(22, restoredState.sampleCount.get())

        val (mean, confidence) = restoredState.calculateBetaPosterior()
        assertTrue("Posterior mean should be high (> 0.8) with 18.5 weighted successes and 2 failures", mean > 0.8)
        assertTrue("Confidence should be high with 22 total samples", confidence > 0.7)
    }

    @Test
    fun testDpiStorageRoundTripRestoresStrategyStateRepository() {
        val testProfile = "wifi-office-5ghz"
        
        // Setup DpiEngine state
        DpiEngine.strategyScores[HostCategory.MESSENGER]?.get(BypassStrategy.FAKE_PACKET)?.set(190)
        DpiEngine.categorySuccessHistory.getOrPut(HostCategory.MESSENGER) { ConcurrentHashMap() }
            .getOrPut(BypassStrategy.FAKE_PACKET) { AtomicInteger(0) }.set(12)
        DpiEngine.categoryFailureHistory.getOrPut(HostCategory.MESSENGER) { ConcurrentHashMap() }
            .getOrPut(BypassStrategy.FAKE_PACKET) { AtomicInteger(0) }.set(1)

        val captured = DpiStorage.captureStrategyProfileState(testProfile)
        assertNotNull(captured)

        // Clear repo and engine
        StrategyStateRepository.resetAll()

        // Restore via DpiStorage
        DpiStorage.restoreStrategyProfileState(captured)

        // Verify that StrategyStateRepository now contains the restored metric for that profile
        val restoredRepoState = StrategyStateRepository.getStrategyState(
            strategy = BypassStrategy.FAKE_PACKET,
            transport = TransportType.TCP,
            category = HostCategory.MESSENGER,
            profileId = testProfile
        )

        assertEquals(190, restoredRepoState.score.get())
        assertEquals(12, restoredRepoState.successCount.get())
        assertEquals(1, restoredRepoState.failureCount.get())
    }
}
