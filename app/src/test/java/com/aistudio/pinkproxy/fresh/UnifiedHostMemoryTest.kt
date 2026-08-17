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
class UnifiedHostMemoryTest {

    @Before
    fun setup() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        BypassConfig.clearScores(context)
        DpiEngine.resetStrategyScoresForNetworkChange()
    }

    @Test
    fun testContextualHostMemoryIsSingleSourceOfTruth() {
        val host = "video-stream.example.com"
        val profile = NetworkProfileManager.currentProfile.value.id
        
        // Record high quality observation for UDP transport
        val obsUdp = StrategyObservation(
            executedStrategy = BypassStrategy.UDP_FRAGMENT_SKEW,
            category = HostCategory.STREAMING,
            host = host,
            success = true,
            quality = ObservationQuality.APPLICATION_DATA_EXCHANGED,
            transport = TransportType.UDP,
            profileId = profile
        )
        DpiStrategySelector.recordObservation(obsUdp)

        // Record high quality observation for TCP transport
        val obsTcp = StrategyObservation(
            executedStrategy = BypassStrategy.TLS_SNI_FRAGMENT,
            category = HostCategory.STREAMING,
            host = host,
            success = true,
            quality = ObservationQuality.APPLICATION_DATA_EXCHANGED,
            transport = TransportType.TCP,
            profileId = profile
        )
        DpiStrategySelector.recordObservation(obsTcp)

        // Ensure contextual host memory stores both distinctly without collision
        val keyUdp = HostContextKey(host, TransportType.UDP, profile)
        val keyTcp = HostContextKey(host, TransportType.TCP, profile)

        assertEquals(BypassStrategy.UDP_FRAGMENT_SKEW, DpiEngine.contextualHostMemory[keyUdp]?.strategy)
        assertEquals(BypassStrategy.TLS_SNI_FRAGMENT, DpiEngine.contextualHostMemory[keyTcp]?.strategy)

        // BypassConfig.getBestStrategyForHost queries DpiEngine and gets exact transport strategy
        val bestUdp = BypassConfig.getBestStrategyForHost(host, TransportType.UDP)
        val bestTcp = BypassConfig.getBestStrategyForHost(host, TransportType.TCP)

        assertEquals(BypassStrategy.UDP_FRAGMENT_SKEW, bestUdp)
        assertEquals(BypassStrategy.TLS_SNI_FRAGMENT, bestTcp)
    }
}
