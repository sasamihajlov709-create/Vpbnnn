package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class StrategyStateRepositoryTest {

    @Before
    fun setUp() {
        StrategyStateRepository.resetAll()
    }

    @Test
    fun testRecordObservationUpdatesStateAndConfidence() {
        val state = StrategyStateRepository.getStrategyState(
            strategy = BypassStrategy.SNI_SPLIT,
            transport = TransportType.TCP,
            category = HostCategory.STREAMING,
            profileId = "profile-1"
        )
        assertEquals(0, state.sampleCount.get())
        assertEquals(0, state.successCount.get())

        val obsSuccess = StrategyObservation(
            executedStrategy = BypassStrategy.SNI_SPLIT,
            transport = TransportType.TCP,
            requestedStrategy = BypassStrategy.SNI_SPLIT,
            effectiveStrategy = BypassStrategy.SNI_SPLIT,
            category = HostCategory.STREAMING,
            host = "video.example.com",
            profileId = "profile-1",
            success = true,
            quality = ObservationQuality.APPLICATION_DATA_EXCHANGED,
            latencyMs = 120L
        )

        StrategyStateRepository.recordObservation(obsSuccess)

        assertEquals(1, state.sampleCount.get())
        assertEquals(1, state.successCount.get())
        assertEquals(1, state.verifiedSuccessCount.get())
        assertTrue("Weighted success should be positive", state.weightedSuccess.get() > 0)
        assertEquals(120L, state.averageLatencyMs)

        val (mean, conf) = state.calculateBetaPosterior()
        assertTrue("Posterior mean should be high on verified success", mean > 0.5)
        assertTrue("Confidence should be within valid bounds", conf in 0.05..0.99)
    }

    @Test
    fun testContextIsolationAcrossTransports() {
        val tcpObs = StrategyObservation(
            executedStrategy = BypassStrategy.SNI_SPLIT,
            transport = TransportType.TCP,
            quality = ObservationQuality.APPLICATION_DATA_EXCHANGED,
            category = HostCategory.STREAMING,
            success = true,
            latencyMs = 40L
        )
        val udpObs = StrategyObservation(
            executedStrategy = BypassStrategy.SNI_SPLIT,
            transport = TransportType.UDP,
            quality = ObservationQuality.CONNECT_ONLY,
            category = HostCategory.STREAMING,
            success = false,
            failureReason = FailureReason.TIMEOUT
        )

        StrategyStateRepository.recordObservation(tcpObs)
        StrategyStateRepository.recordObservation(udpObs)

        val tcpState = StrategyStateRepository.getStrategyState(
            strategy = BypassStrategy.SNI_SPLIT,
            transport = TransportType.TCP,
            category = HostCategory.STREAMING
        )
        val udpState = StrategyStateRepository.getStrategyState(
            strategy = BypassStrategy.SNI_SPLIT,
            transport = TransportType.UDP,
            category = HostCategory.STREAMING
        )

        assertEquals(1, tcpState.successCount.get())
        assertEquals(0, tcpState.failureCount.get())
        assertEquals(0, udpState.successCount.get())
        assertEquals(1, udpState.failureCount.get())
    }

    @Test
    fun testConfidenceDifferentiatesSampleVolume() {
        val lowSampleState = StrategyState(strategy = BypassStrategy.SNI_SPLIT)
        val highSampleState = StrategyState(strategy = BypassStrategy.FAKE_PACKET)

        // 1 success out of 1
        lowSampleState.recordObservation(
            StrategyObservation(
                executedStrategy = BypassStrategy.SNI_SPLIT,
                transport = TransportType.TCP,
                requestedStrategy = BypassStrategy.SNI_SPLIT,
                effectiveStrategy = BypassStrategy.SNI_SPLIT,
                category = HostCategory.OTHER,
                host = "site1.com",
                profileId = "def",
                success = true,
                quality = ObservationQuality.APPLICATION_DATA_EXCHANGED,
                latencyMs = 50L
            )
        )

        // 50 successes out of 50
        for (i in 1..50) {
            highSampleState.recordObservation(
                StrategyObservation(
                    executedStrategy = BypassStrategy.FAKE_PACKET,
                    transport = TransportType.TCP,
                    requestedStrategy = BypassStrategy.FAKE_PACKET,
                    effectiveStrategy = BypassStrategy.FAKE_PACKET,
                    category = HostCategory.OTHER,
                    host = "site2.com",
                    profileId = "def",
                    success = true,
                    quality = ObservationQuality.APPLICATION_DATA_EXCHANGED,
                    latencyMs = 50L
                )
            )
        }

        val lowConf = lowSampleState.calculateConfidence()
        val highConf = highSampleState.calculateConfidence()

        assertTrue("High sample volume must yield significantly higher confidence than a single sample ($highConf > $lowConf)", highConf > lowConf)
    }
}
