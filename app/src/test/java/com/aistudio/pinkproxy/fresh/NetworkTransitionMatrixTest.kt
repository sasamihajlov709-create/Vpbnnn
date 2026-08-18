package com.aistudio.pinkproxy.fresh

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Validates network transition resilience (Wi-Fi <-> Mobile LTE <-> No Connectivity)
 * ensuring contextual memory isolation and stable recovery behavior.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class NetworkTransitionMatrixTest {

    private lateinit var context: Context

    @Before
    fun setup() {
        context = ApplicationProvider.getApplicationContext()
        BypassConfig.clearScores(context)
        DpiEngine.resetStrategyScoresForNetworkChange()
    }

    @Test
    fun testNetworkProfileSwitchingIsolatesState() = runBlocking {
        val wifiProfile = NetworkProfile(
            id = "wifi_home_net",
            type = NetworkType.WIFI,
            displayName = "Home WiFi"
        )

        val lteProfile = NetworkProfile(
            id = "cellular_lte_net",
            type = NetworkType.MOBILE,
            displayName = "Mobile LTE"
        )

        // 1. In Wi-Fi profile, train YouTube on SNI_SPLIT
        NetworkProfileManager.setProfileForTesting(wifiProfile)
        DpiStrategySelector.recordResult(
            strategy = BypassStrategy.SNI_SPLIT,
            success = true,
            category = HostCategory.STREAMING,
            latencyMs = 20L,
            host = "googlevideo.com",
            quality = ObservationQuality.APPLICATION_DATA_EXCHANGED,
            transport = TransportType.TCP
        )

        val wifiChosen = DpiStrategySelector.getBestStrategy(HostCategory.STREAMING, "googlevideo.com", TransportType.TCP)
        assertEquals(BypassStrategy.SNI_SPLIT, wifiChosen)

        // 2. Switch network profile to LTE
        NetworkProfileManager.setProfileForTesting(lteProfile)
        DpiEngine.switchNetworkProfile(wifiProfile, lteProfile, context)

        // 3. Under LTE, train different optimal strategy (e.g. TLS_SNI_EXT_MANGLE)
        DpiStrategySelector.recordResult(
            strategy = BypassStrategy.TLS_SNI_EXT_MANGLE,
            success = true,
            category = HostCategory.STREAMING,
            latencyMs = 45L,
            host = "googlevideo.com",
            quality = ObservationQuality.APPLICATION_DATA_EXCHANGED,
            transport = TransportType.TCP
        )

        val lteChosen = DpiStrategySelector.getBestStrategy(HostCategory.STREAMING, "googlevideo.com", TransportType.TCP)
        assertEquals(BypassStrategy.TLS_SNI_EXT_MANGLE, lteChosen)

        // 4. Switch back to Wi-Fi - ensure isolated memory correctly reflects Wi-Fi history
        NetworkProfileManager.setProfileForTesting(wifiProfile)
        val wifiRestored = DpiStrategySelector.getBestStrategy(HostCategory.STREAMING, "googlevideo.com", TransportType.TCP)
        assertEquals(BypassStrategy.SNI_SPLIT, wifiRestored)
    }
}
