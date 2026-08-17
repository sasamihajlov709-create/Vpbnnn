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
@Config(sdk = [34])
class TtlMtuPersistenceAndTrafficTest {

    private lateinit var context: Context

    @Before
    fun setup() {
        context = ApplicationProvider.getApplicationContext()
        TrafficMonitor.reset()
    }

    @Test
    fun testTtlMtuPerProfilePersistence() {
        val profileId = NetworkProfileManager.currentProfile.value.id
        AutoTtlProber.setDiscoveredTtl("video.example.com", 6, profileId)
        AutoTtlProber.setDiscoveredMtu("video.example.com", 1380, profileId)

        assertEquals(6, AutoTtlProber.getDiscoveredTtl("video.example.com"))
        assertEquals(1380, AutoTtlProber.getDiscoveredMtu("video.example.com"))

        // Save via AutoTtlProber
        AutoTtlProber.saveTtlMtuState(context, profileId)

        // Reset in-memory state
        AutoTtlProber.setDiscoveredTtl("video.example.com", 0, profileId)
        AutoTtlProber.setDiscoveredMtu("video.example.com", 0, profileId)

        // Load back
        AutoTtlProber.loadTtlMtuState(context, profileId)

        assertEquals(6, AutoTtlProber.getDiscoveredTtl("video.example.com"))
        assertEquals(1380, AutoTtlProber.getDiscoveredMtu("video.example.com"))
    }

    @Test
    fun testTrafficMonitorSpeedAndTopHosts() {
        TrafficMonitor.updateBytes(1024 * 1024) // 1MB
        TrafficMonitor.updateConnections(5)
        assertEquals(5, TrafficMonitor.activeConnections.value)

        TrafficMonitor.addTraffic("youtube.com")
        TrafficMonitor.addTraffic("youtube.com")
        TrafficMonitor.addTraffic("telegram.org")

        val hosts = TrafficMonitor.topHosts.value
        assertEquals(2, hosts.size)
        assertEquals("youtube.com", hosts[0].first)
        assertEquals(2, hosts[0].second)

        TrafficMonitor.updateSpeedMetrics()
        assertEquals(1024 * 1024L, TrafficMonitor.speedBytesPerSecond.value)
        assertEquals(1, TrafficMonitor.speedHistory.value.size)

        TrafficMonitor.reset()
        assertEquals(0L, TrafficMonitor.bytesTransferred.value)
        assertEquals(0, TrafficMonitor.activeConnections.value)
        assertTrue(TrafficMonitor.topHosts.value.isEmpty())
    }

    @Test
    fun testActiveFlowDataIntegrity() {
        val flow = ActiveFlow(
            id = "flow_123",
            host = "api.telegram.org",
            type = "TCP",
            strategy = BypassStrategy.TCP_COMBINED_HYBRID,
            reasoning = "High success rate on Messenger category",
            bytesSent = 1024L,
            bytesReceived = 4096L
        )

        assertEquals("api.telegram.org", flow.host)
        assertEquals("TCP", flow.type)
        assertEquals(BypassStrategy.TCP_COMBINED_HYBRID, flow.strategy)
        assertEquals(4096L, flow.bytesReceived)
        assertEquals(1024L, flow.bytesSent)
        assertEquals("ACTIVE", flow.status)
    }

    @Test
    fun testNoiseGeneratorSizesAndEntropy() {
        val smallNoise = NoiseGenerator.getSmallNoise(64)
        assertEquals(64, smallNoise.size)
        
        val zeroNoise = NoiseGenerator.getSmallNoise(0)
        assertEquals(0, zeroNoise.size)

        val udpNoise = NoiseGenerator.buildUdpNoise(128)
        assertEquals(128, udpNoise.size)
        
        // Verify buffer is not all zeros
        assertTrue(udpNoise.any { it != 0.toByte() })
    }

    @Test
    fun testProxyStatsMssAdaptationAndFormatBytes() {
        ProxyStats.updateMaxMss(1460)
        ProxyStats.resetMssFailureCount()
        assertEquals(1460, ProxyStats.maxMss.value)
        assertEquals(0, ProxyStats.mssFailureCount.value)

        // Increment 3 times to trigger MSS backoff
        ProxyStats.recordMssFailure()
        ProxyStats.recordMssFailure()
        ProxyStats.recordMssFailure()
        assertEquals(1332, ProxyStats.maxMss.value)

        // Verify formatBytes
        assertEquals("0 B", ProxyStats.formatBytes(0))
        assertEquals("512 B", ProxyStats.formatBytes(512))
        assertEquals("1.0 KB", ProxyStats.formatBytes(1024))
        assertEquals("1.0 MB", ProxyStats.formatBytes(1024 * 1024))
    }

    @Test
    fun testBypassConfigDualTransportMemoryIsolation() {
        val host = "discord.gg"
        
        val tcpStrat = BypassConfig.getBestStrategyForHost(host, TransportType.TCP)
        val udpStrat = BypassConfig.getBestStrategyForHost(host, TransportType.UDP)
        
        assertTrue(DpiStrategySelector.isFamilyCompatible(tcpStrat.family, TransportType.TCP))
        assertTrue(DpiStrategySelector.isFamilyCompatible(udpStrat.family, TransportType.UDP))
    }

    @Test
    fun testObservationQualityMaturityWeightsAndDeterministicFallback() {
        val strategy = BypassStrategy.SNI_SPLIT
        DpiEngine.strategyMaturity[strategy]?.set(0)

        // Weak signal (CONNECT_ONLY) should not advance maturity
        val weakObs = StrategyObservation(
            executedStrategy = strategy,
            transport = TransportType.TCP,
            success = true,
            quality = ObservationQuality.CONNECT_ONLY
        )
        DpiStrategySelector.recordObservation(weakObs)
        assertEquals(0, DpiEngine.strategyMaturity[strategy]?.get() ?: 0)

        // Strong signal (APPLICATION_DATA_EXCHANGED) should advance maturity
        val strongObs = StrategyObservation(
            executedStrategy = strategy,
            transport = TransportType.TCP,
            success = true,
            quality = ObservationQuality.APPLICATION_DATA_EXCHANGED
        )
        DpiStrategySelector.recordObservation(strongObs)
        assertEquals(2, DpiEngine.strategyMaturity[strategy]?.get())

        // Test deterministic diverse fallback repeatability
        val fb1 = DpiStrategySelector.getDiverseFallback(failed = BypassStrategy.DIRECT, transport = TransportType.TCP)
        val fb2 = DpiStrategySelector.getDiverseFallback(failed = BypassStrategy.DIRECT, transport = TransportType.TCP)
        assertEquals(fb1, fb2)
    }
}

