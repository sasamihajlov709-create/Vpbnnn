package com.aistudio.pinkproxy.fresh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class CandidateHierarchicalPriorTest {

    @Before
    fun setup() {
        StrategyStateRepository.clearProfileState("default")
        BypassConfig.isAutoTuning = true
    }

    @Test
    fun testHierarchicalPriorPrioritizesCategory() {
        val transport = TransportType.TCP
        val profileId = "default"
        val category = HostCategory.STREAMING

        // Let's pretend TLS_RECORD_FRAGMENTATION is very successful for STREAMING category
        val strategy1 = BypassStrategy.TLS_RECORD_FRAGMENTATION
        val strategy2 = BypassStrategy.TLS_SNI_EXT_MANGLE

        // Feed some successes to strategy1 specifically for STREAMING category
        for (i in 1..20) {
            val obs = StrategyObservation(
                executedStrategy = strategy1,
                transport = transport,
                category = category,
                profileId = profileId,
                success = true,
                latencyMs = 100,
                failureReason = null, quality = ObservationQuality.APPLICATION_DATA_EXCHANGED,
                timestamp = System.currentTimeMillis()
            )
            StrategyStateRepository.recordObservation(obs)
        }

        // Now, we want to rank candidates for a NEW host in STREAMING category
        // that we have NO host-specific memory for.
        val context = CandidateEngine.SelectionContext(
            transport = transport,
            profileId = profileId,
            host = "new-streaming-site.com",
            category = category
        )

        val engine = CandidateEngine
        val candidates = listOf(strategy2, strategy1) // Provide in reverse order to ensure it gets sorted

        // Strategy 1 should have a much higher alpha because of the category prior
        val ranked = engine.rankCandidatesBayesian(candidates, context)

        // The first candidate should be TLS_RECORD_FRAGMENTATION
        assertEquals(BypassStrategy.TLS_RECORD_FRAGMENTATION, ranked.first())
    }
}
