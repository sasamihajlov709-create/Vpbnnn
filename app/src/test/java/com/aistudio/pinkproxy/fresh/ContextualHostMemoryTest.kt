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
class ContextualHostMemoryTest {

    @Before
    fun setup() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        BypassConfig.clearScores(context)
        DpiEngine.resetStrategyScoresForNetworkChange()
        DpiEngine.contextualHostMemory.clear()
        DpiEngine.hostSpecificMemory.clear()
    }

    @Test
    fun testTransportIsolationInHostMemory() {
        val host = "video-stream.service.com"
        val tcpStrat = BypassStrategy.TLS_SNI_FRAGMENT
        val udpStrat = BypassStrategy.UDP_NOISE_CHAOS

        // Record successful application data transfer over TCP
        val tcpObs = StrategyObservation(
            executedStrategy = tcpStrat,
            transport = TransportType.TCP,
            category = HostCategory.STREAMING,
            host = host,
            profileId = "home_wifi",
            success = true,
            quality = ObservationQuality.APPLICATION_DATA_EXCHANGED
        )
        DpiStrategySelector.recordObservation(tcpObs)

        // Record successful application data transfer over UDP
        val udpObs = StrategyObservation(
            executedStrategy = udpStrat,
            transport = TransportType.UDP,
            category = HostCategory.STREAMING,
            host = host,
            profileId = "home_wifi",
            success = true,
            quality = ObservationQuality.APPLICATION_DATA_EXCHANGED
        )
        DpiStrategySelector.recordObservation(udpObs)

        // Verify TCP key returns TCP strategy
        val tcpKey = HostContextKey(host, TransportType.TCP, "home_wifi")
        val tcpMem = DpiEngine.contextualHostMemory[tcpKey]
        assertNotNull("TCP context should be preserved", tcpMem)
        assertEquals(tcpStrat, tcpMem?.strategy)
        assertEquals(TransportType.TCP, tcpMem?.transport)

        // Verify UDP key returns UDP strategy
        val udpKey = HostContextKey(host, TransportType.UDP, "home_wifi")
        val udpMem = DpiEngine.contextualHostMemory[udpKey]
        assertNotNull("UDP context should be preserved", udpMem)
        assertEquals(udpStrat, udpMem?.strategy)
        assertEquals(TransportType.UDP, udpMem?.transport)
    }

    @Test
    fun testProfileIsolationInHostMemory() {
        val host = "social-media.network.org"
        val wifiStrat = BypassStrategy.SNI_SPLIT
        val lteStrat = BypassStrategy.TCP_REARRANGE_CHUNKS

        // Wifi profile record
        DpiStrategySelector.recordObservation(
            StrategyObservation(
                executedStrategy = wifiStrat,
                transport = TransportType.TCP,
                category = HostCategory.SOCIAL,
                host = host,
                profileId = "profile_wifi_isp_a",
                success = true,
                quality = ObservationQuality.APPLICATION_DATA_EXCHANGED
            )
        )

        // LTE profile record
        DpiStrategySelector.recordObservation(
            StrategyObservation(
                executedStrategy = lteStrat,
                transport = TransportType.TCP,
                category = HostCategory.SOCIAL,
                host = host,
                profileId = "profile_lte_carrier_b",
                success = true,
                quality = ObservationQuality.APPLICATION_DATA_EXCHANGED
            )
        )

        val wifiKey = HostContextKey(host, TransportType.TCP, "profile_wifi_isp_a")
        val lteKey = HostContextKey(host, TransportType.TCP, "profile_lte_carrier_b")

        assertEquals(wifiStrat, DpiEngine.contextualHostMemory[wifiKey]?.strategy)
        assertEquals(lteStrat, DpiEngine.contextualHostMemory[lteKey]?.strategy)
    }
}
