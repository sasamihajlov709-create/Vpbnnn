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
class CanonicalObservationQualityTest {

    @Before
    fun setup() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        BypassConfig.clearScores(context)
        DpiEngine.resetStrategyScoresForNetworkChange()
    }

    @Test
    fun testObservationQualityGraduation() {
        val testHost = "sensitive-censor-test.org"
        val testStrat = BypassStrategy.TLS_SNI_FRAGMENT

        // 1. Weak signal (CONNECT_ONLY) should not lock in persistent host memory
        val obsWeak = StrategyObservation(
            executedStrategy = testStrat,
            category = HostCategory.OTHER,
            host = testHost,
            success = true,
            quality = ObservationQuality.CONNECT_ONLY,
            latencyMs = 25
        )
        DpiStrategySelector.recordObservation(obsWeak)
        assertNull("CONNECT_ONLY must not populate hostSpecificMemory", DpiEngine.hostSpecificMemory[testHost])
        assertEquals("CONNECT_ONLY must not increment verifiedSuccessHistory", 0, DpiEngine.verifiedSuccessHistory[testStrat]?.get() ?: 0)
        assertEquals("CONNECT_ONLY increments raw successHistory", 1, DpiEngine.successHistory[testStrat]?.get() ?: 0)

        // 2. Weak signal (TLS_RECORD_RECEIVED) should still not lock in persistent host memory
        val obsTlsRecord = StrategyObservation(
            executedStrategy = testStrat,
            category = HostCategory.OTHER,
            host = testHost,
            success = true,
            quality = ObservationQuality.TLS_RECORD_RECEIVED,
            latencyMs = 30
        )
        DpiStrategySelector.recordObservation(obsTlsRecord)
        assertNull("TLS_RECORD_RECEIVED must not lock persistent host memory before app data", DpiEngine.hostSpecificMemory[testHost])

        // 3. Application level signal (APPLICATION_DATA_EXCHANGED) confirms bypass and locks memory
        val obsApp = StrategyObservation(
            executedStrategy = testStrat,
            category = HostCategory.OTHER,
            host = testHost,
            success = true,
            quality = ObservationQuality.APPLICATION_DATA_EXCHANGED,
            latencyMs = 45
        )
        DpiStrategySelector.recordObservation(obsApp)
        assertNotNull("APPLICATION_DATA_EXCHANGED must lock in hostSpecificMemory", DpiEngine.hostSpecificMemory[testHost])
        assertEquals(testStrat, DpiEngine.hostSpecificMemory[testHost]?.strategy)
    }

    @Test
    fun testStrategyStateBayesianConfidenceCalculation() {
        val state = StrategyState(BypassStrategy.SNI_SPLIT)
        assertEquals(0.1, state.calculateConfidence(), 0.05)

        // Record several high quality observations
        for (i in 1..8) {
            state.recordObservation(
                StrategyObservation(
                    executedStrategy = BypassStrategy.SNI_SPLIT,
                    success = true,
                    quality = ObservationQuality.APPLICATION_DATA_EXCHANGED,
                    latencyMs = 30
                )
            )
        }

        val conf = state.calculateConfidence()
        assertTrue("Confidence should grow above 0.5 with 8 successful samples (got $conf)", conf > 0.5)
        assertEquals(30L, state.averageLatencyMs)
    }
}
