package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.net.UnknownHostException
import java.io.IOException

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], manifest = Config.NONE)
class DnsFailureIsolationTest {

    @Before
    fun setup() {
        StrategyStateRepository.getAllContextStates()
    }

    @Test
    fun `test UnknownHostException does not penalize strategy`() {
        val strategy = BypassStrategy.SNI_SPLIT
        val host = "unknown-domain.com"
        
        // Ensure starting from clean slate
        val initialState = StrategyStateRepository.getStrategyState(strategy, TransportType.TCP, HostCategory.OTHER, "DEFAULT")
        assertEquals(0, initialState.failureCount.get())

        // Simulate a DNS failure being reported as a strategy result
        DpiStrategySelector.recordResult(
            strategy = strategy,
            success = false,
            transport = TransportType.TCP,
            latencyMs = 50,
            host = host,
            quality = ObservationQuality.CONNECT_ONLY,
            reason = FailureReason.DNS_RESOLUTION_FAILED,
            profileId = "DEFAULT"
        )

        // The failure count should remain 0 because UnknownHostException should be ignored
        val updatedState = StrategyStateRepository.getStrategyState(strategy, TransportType.TCP, HostCategory.OTHER, "DEFAULT")
        assertEquals(0, updatedState.failureCount.get())
    }
    
    @Test
    fun `test IOException DOES penalize strategy`() {
        val strategy = BypassStrategy.SNI_SPLIT
        val host = "normal-domain.com"
        
        // Ensure starting from clean slate
        val initialState = StrategyStateRepository.getStrategyState(strategy, TransportType.TCP, HostCategory.OTHER, "DEFAULT")
        assertEquals(0, initialState.failureCount.get())

        // Simulate a standard network failure
        DpiStrategySelector.recordResult(
            strategy = strategy,
            success = false,
            transport = TransportType.TCP,
            latencyMs = 50,
            host = host,
            quality = ObservationQuality.CONNECT_ONLY,
            reason = FailureReason.CONNECTION_REFUSED,
            profileId = "DEFAULT"
        )

        // The failure count should increase
        val updatedState = StrategyStateRepository.getStrategyState(strategy, TransportType.TCP, HostCategory.OTHER, "DEFAULT")
        assertEquals(1, updatedState.failureCount.get())
    }
}
