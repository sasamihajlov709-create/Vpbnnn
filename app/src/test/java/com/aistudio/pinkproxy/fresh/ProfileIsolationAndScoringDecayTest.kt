package com.aistudio.pinkproxy.fresh

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.util.concurrent.atomic.AtomicInteger

@RunWith(RobolectricTestRunner::class)
class ProfileIsolationAndScoringDecayTest {

    @Test
    fun testProfileStorageIsolation() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val profileA = "wifi_profile_aaa"
        val profileB = "cell_profile_bbb"

        // Set specific scores for Profile A
        DpiEngine.strategyScores[HostCategory.OTHER]?.get(BypassStrategy.SNI_SPLIT)?.set(500)
        DpiEngine.strategyScores[HostCategory.OTHER]?.get(BypassStrategy.TCP_PULSE_FRAG)?.set(40)
        DpiEngine.hostSpecificMemory["host-a.com"] = DpiEngine.HostMemory(BypassStrategy.SNI_SPLIT, System.currentTimeMillis(), 5)
        AutoTtlProber.setDiscoveredTtl("host-a.com", 12, profileA)
        AutoTtlProber.setDiscoveredMtu("host-a.com", 1320, profileA)

        // Save Profile A
        DpiStorage.saveProfileScores(context, profileA, synchronous = true)
        DpiStorage.saveProfileScores(context, profileA, synchronous = true)

        // Reset in-memory states and set for Profile B
        DpiEngine.strategyScores[HostCategory.OTHER]?.get(BypassStrategy.SNI_SPLIT)?.set(100)
        DpiEngine.strategyScores[HostCategory.OTHER]?.get(BypassStrategy.TCP_PULSE_FRAG)?.set(850)
        DpiEngine.hostSpecificMemory.clear()
        DpiEngine.hostSpecificMemory["host-b.com"] = DpiEngine.HostMemory(BypassStrategy.TCP_PULSE_FRAG, System.currentTimeMillis(), 3)
        AutoTtlProber.setDiscoveredTtl("host-b.com", 18, profileB)
        AutoTtlProber.setDiscoveredMtu("host-b.com", 1280, profileB)

        // Save Profile B
        DpiStorage.saveProfileScores(context, profileB, synchronous = true)

        // Now load Profile A and verify isolation
        DpiStorage.loadProfileScores(context, profileA)
        AutoTtlProber.loadTtlMtuState(context, profileA)

        assertEquals(500, DpiEngine.strategyScores[HostCategory.OTHER]?.get(BypassStrategy.SNI_SPLIT)?.get())
        assertEquals(40, DpiEngine.strategyScores[HostCategory.OTHER]?.get(BypassStrategy.TCP_PULSE_FRAG)?.get())
        assertTrue(DpiEngine.hostSpecificMemory.containsKey("host-a.com"))
        assertFalse(DpiEngine.hostSpecificMemory.containsKey("host-b.com"))
        assertEquals(12, AutoTtlProber.getDiscoveredTtl("host-a.com"))
        assertEquals(1320, AutoTtlProber.getDiscoveredMtu("host-a.com"))

        // Load Profile B and verify isolation
        DpiStorage.loadProfileScores(context, profileB)
        AutoTtlProber.loadTtlMtuState(context, profileB)

        assertEquals(100, DpiEngine.strategyScores[HostCategory.OTHER]?.get(BypassStrategy.SNI_SPLIT)?.get())
        assertEquals(850, DpiEngine.strategyScores[HostCategory.OTHER]?.get(BypassStrategy.TCP_PULSE_FRAG)?.get())
        assertTrue(DpiEngine.hostSpecificMemory.containsKey("host-b.com"))
        assertFalse(DpiEngine.hostSpecificMemory.containsKey("host-a.com"))
        assertEquals(18, AutoTtlProber.getDiscoveredTtl("host-b.com"))
        assertEquals(1280, AutoTtlProber.getDiscoveredMtu("host-b.com"))
    }

    @Test
    fun testMathematicalScoreDecayWithoutArtificialInflation() {
        // Given a penalized strategy score below 100
        DpiEngine.strategyScores[HostCategory.OTHER]?.get(BypassStrategy.TCP_RST_FAKE)?.set(40)
        ProxyStats.updateCensorshipIntensity(20) // low censorship intensity -> decay = 0.95

        // Run analysis and adjustment
        DpiAnalyzer.analyzeAndAdjust()

        val decayedScore = DpiEngine.strategyScores[HostCategory.OTHER]?.get(BypassStrategy.TCP_RST_FAKE)?.get() ?: 0
        // Expected value: (40 * 0.95 + 100 * 0.05) = 38 + 5 = 43
        assertEquals(43, decayedScore)
        assertNotEquals("Score must not be arbitrary +2 jump (42)", 42, decayedScore)

        // Given a high score > 100
        DpiEngine.strategyScores[HostCategory.OTHER]?.get(BypassStrategy.SNI_SPLIT)?.set(300)
        DpiAnalyzer.analyzeAndAdjust()
        val decayedHighScore = DpiEngine.strategyScores[HostCategory.OTHER]?.get(BypassStrategy.SNI_SPLIT)?.get() ?: 0
        // Expected value: (300 * 0.95 + 100 * 0.05) = 285 + 5 = 290
        assertEquals(290, decayedHighScore)
    }

    @Test
    fun testThompsonSamplerSamplingBounds() {
        for (i in 0 until 100) {
            val sampleLow = ThompsonSampler.sampleBeta(1.0, 50.0)
            assertTrue("Sample with heavy failure should be < 0.2", sampleLow < 0.2)

            val sampleHigh = ThompsonSampler.sampleBeta(50.0, 1.0)
            assertTrue("Sample with high success should be > 0.8", sampleHigh > 0.8)

            val sampleBalanced = ThompsonSampler.sampleBeta(10.0, 10.0)
            assertTrue("Sample balanced should be between 0.0001 and 0.9999", sampleBalanced in 0.0001..0.9999)
        }
    }
}
