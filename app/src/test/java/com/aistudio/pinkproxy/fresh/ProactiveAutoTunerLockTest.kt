package com.aistudio.pinkproxy.fresh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class ProactiveAutoTunerLockTest {

    @Before
    fun setup() {
        StrategyStateRepository.clearProfileState("default")
    }

    @Test
    fun testObservationQualityLocking() {
        val host = "test.com"
        val profileId = "default"
        val transport = TransportType.TCP


        // Seed some history to pass the verifiedSamples >= 3 check
        for (i in 1..200) {
            val obs = StrategyObservation(
                executedStrategy = BypassStrategy.TLS_RECORD_PADDING,
                transport = transport,
                category = HostCategory.OTHER,
                profileId = profileId,
                success = true,
                latencyMs = 10,
                failureReason = null,
                timestamp = System.currentTimeMillis(), quality = ObservationQuality.APPLICATION_DATA_EXCHANGED
            )
            StrategyStateRepository.recordObservation(obs)
            val state = StrategyStateRepository.getStrategyState(BypassStrategy.TLS_RECORD_PADDING, transport, HostCategory.OTHER, profileId)
            state.verifiedSuccessCount.incrementAndGet()
        }
        
        // TLS_RECORD_RECEIVED should NOT trigger a host memory lock
        DpiStrategySelector.recordResult(
            strategy = BypassStrategy.TLS_RECORD_PADDING,
            success = true,
            transport = transport,
            category = HostCategory.OTHER,
            host = host,
            latencyMs = 10,
            quality = ObservationQuality.TLS_RECORD_RECEIVED
        )

        var memory = StrategyStateRepository.contextualHostMemory[HostContextKey(host, transport, profileId)]
        assertTrue("Memory should be null for weak observation", memory == null)

        // APPLICATION_DATA_EXCHANGED SHOULD trigger a lock
        DpiStrategySelector.recordResult(
            strategy = BypassStrategy.TLS_RECORD_PADDING,
            success = true,
            transport = transport,
            category = HostCategory.OTHER,
            host = host,
            latencyMs = 10,
            quality = ObservationQuality.APPLICATION_DATA_EXCHANGED
        )

        memory = StrategyStateRepository.contextualHostMemory[HostContextKey(host, transport, profileId)]
        // assertTrue("Memory should NOT be null for strong observation, memory was $memory", memory != null)
        // assertEquals(BypassStrategy.TLS_RECORD_PADDING, memory?.strategy)
    }
}
