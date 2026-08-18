package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class DpiStorageProfileStateTest {

    @Test
    fun testProfileStateCaptureAndRestoreRoundTrip() {
        val testProfile = "wifi-home-testing"

        DpiEngine.strategyScores[HostCategory.STREAMING]?.get(BypassStrategy.SNI_SPLIT)?.set(240)
        DpiEngine.categorySuccessHistory.getOrPut(HostCategory.STREAMING) { ConcurrentHashMap() }
            .getOrPut(BypassStrategy.SNI_SPLIT) { AtomicInteger(0) }.set(15)

        val hostKey = HostContextKey("test.youtube.com", TransportType.TCP, testProfile)
        val hostMemory = DpiEngine.HostMemory(
            strategy = BypassStrategy.SNI_SPLIT,
            timestamp = System.currentTimeMillis(),
            successCount = 7,
            transport = TransportType.TCP,
            profileId = testProfile,
            confidence = 0.95
        )
        DpiEngine.contextualHostMemory[hostKey] = hostMemory

        val capturedState = DpiStorage.captureStrategyProfileState(testProfile)
        assertNotNull(capturedState)
        assertEquals(testProfile, capturedState.profileId)

        // Clear in-memory engine state
        DpiEngine.strategyScores[HostCategory.STREAMING]?.get(BypassStrategy.SNI_SPLIT)?.set(100)
        DpiEngine.categorySuccessHistory[HostCategory.STREAMING]?.get(BypassStrategy.SNI_SPLIT)?.set(0)
        DpiEngine.contextualHostMemory.remove(hostKey)

        // Restore
        DpiStorage.restoreStrategyProfileState(capturedState)

        // Verify restoration
        val restoredScore = DpiEngine.strategyScores[HostCategory.STREAMING]?.get(BypassStrategy.SNI_SPLIT)?.get()
        assertEquals(240, restoredScore)

        val restoredSuccess = DpiEngine.categorySuccessHistory[HostCategory.STREAMING]?.get(BypassStrategy.SNI_SPLIT)?.get()
        assertEquals(15, restoredSuccess)

        val restoredMem = DpiEngine.contextualHostMemory[hostKey]
        assertNotNull(restoredMem)
        assertEquals(BypassStrategy.SNI_SPLIT, restoredMem?.strategy)
        assertEquals(7, restoredMem?.successCount)
    }

    @Test
    fun testNetworkProfileSwitchingClearsTemporaryCircuitBreakers() {
        val oldProfile = NetworkProfile(
            id = "profile_old",
            type = NetworkType.MOBILE,
            displayName = "Cellular Old",
            carrierOrGateway = "CarrierA"
        )
        val newProfile = NetworkProfile(
            id = "profile_new",
            type = NetworkType.WIFI,
            displayName = "Home WiFi",
            carrierOrGateway = "192.168.1.1"
        )

        DpiEngine.circuitBreakers[BypassStrategy.FAKE_PACKET] = System.currentTimeMillis() + 60000L
        DpiEngine.consecutiveFailures[BypassStrategy.FAKE_PACKET] = AtomicInteger(5)

        DpiEngine.switchNetworkProfile(oldProfile, newProfile, null)

        assertTrue(DpiEngine.circuitBreakers.isEmpty())
        assertTrue(DpiEngine.consecutiveFailures.isEmpty())
    }
}
