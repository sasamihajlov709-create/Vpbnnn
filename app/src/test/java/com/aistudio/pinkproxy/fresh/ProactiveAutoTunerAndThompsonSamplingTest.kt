package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Test

class ProactiveAutoTunerAndThompsonSamplingTest {

    @Test
    fun testThompsonSamplerBetaDistributionBounds() {
        // Test high success prior: alpha >> beta
        var sampleSumHigh = 0.0
        val runs = 100
        for (i in 0 until runs) {
            val s = ThompsonSampler.sampleBeta(50.0, 2.0)
            assertTrue("Sample must be within (0, 1)", s in 0.0001..0.9999)
            sampleSumHigh += s
        }
        val meanHigh = sampleSumHigh / runs
        assertTrue("High alpha should result in high mean score (> 0.8)", meanHigh > 0.8)

        // Test high failure prior: beta >> alpha
        var sampleSumLow = 0.0
        for (i in 0 until runs) {
            val s = ThompsonSampler.sampleBeta(2.0, 50.0)
            assertTrue("Sample must be within (0, 1)", s in 0.0001..0.9999)
            sampleSumLow += s
        }
        val meanLow = sampleSumLow / runs
        assertTrue("High beta should result in low mean score (< 0.2)", meanLow < 0.2)
    }

    @Test
    fun testThompsonSamplerEdgeValues() {
        val s1 = ThompsonSampler.sampleBeta(0.0, 0.0)
        assertTrue(s1 in 0.0001..0.9999)

        val s2 = ThompsonSampler.sampleBeta(-5.0, 10.0)
        assertTrue(s2 in 0.0001..0.9999)
    }

    @Test
    fun testProactiveObservationPersistence() {
        val targetHost = "rr1---sn-axq7sn76.googlevideo.com"
        val strat = BypassStrategy.BYEBYEDPI_HYBRID
        
        DpiEngine.recordStrategyResult(
            host = targetHost,
            strat = strat,
            success = true,
            latencyMs = 35L,
            quality = ObservationQuality.APPLICATION_DATA_EXCHANGED,
            transport = TransportType.TCP
        )

        val profileId = NetworkProfileManager.currentProfile.value.id
        val mem = DpiEngine.contextualHostMemory[HostContextKey(targetHost, TransportType.TCP, profileId)]
        assertNotNull(mem)
        assertEquals(strat, mem?.strategy)
        assertEquals(TransportType.TCP, mem?.transport)
    }
}
