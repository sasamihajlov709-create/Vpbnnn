package com.aistudio.pinkproxy.fresh

import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], manifest = Config.NONE)
class StrategyStateTest {

    @Test
    fun `test temporal decay reduces weight over time`() {
        val state = StrategyState()
        
        // Initial success
        val obs1 = StrategyObservation(
            executedStrategy = BypassStrategy.SNI_SPLIT,
            transport = TransportType.TCP,
            profileId = "DEFAULT",
            success = true,
            quality = ObservationQuality.APPLICATION_DATA_EXCHANGED
        )
        state.recordObservation(obs1)
        
        val initialWeight = state.weightedSuccess.get()
        assertTrue(initialWeight > 0)
        
        // Simulate time passing (30 minutes)
        val now = System.currentTimeMillis()
        state.lastUsedTimestamp.set(now - 30 * 60000L) // 30 minutes ago
        
        // Next observation triggers decay
        val obs2 = obs1.copy(timestamp = now)
        state.recordObservation(obs2)
        
        val finalWeight = state.weightedSuccess.get()
        assertTrue(finalWeight > 0)
        
        // If it decayed by ~27% + added the new weight, it should be less than initialWeight * 2
        // Since ObservationQuality weight is constant, the new delta is same as initial.
        assertTrue(finalWeight < initialWeight * 2)
    }
}
