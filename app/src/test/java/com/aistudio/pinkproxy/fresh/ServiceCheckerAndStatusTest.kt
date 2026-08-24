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
class ServiceCheckerAndStatusTest {

    private lateinit var context: Context

    @Before
    fun setup() {
        context = ApplicationProvider.getApplicationContext()
    }

    @Test
    fun testCustomServicesAddRemoveAndPersistence() {
        PinkServiceStatusManager.addCustomService(context, "MyWiki", "https://en.wikipedia.org")
        
        var services = PinkServiceStatusManager.customServices.value
        assertEquals(1, services.size)
        assertEquals("MyWiki", services[0].first)
        assertEquals("https://en.wikipedia.org", services[0].second)

        // Reload from prefs
        PinkServiceStatusManager.loadCustomServices(context)
        services = PinkServiceStatusManager.customServices.value
        assertEquals(1, services.size)
        assertEquals("MyWiki", services[0].first)

        // Remove custom service
        PinkServiceStatusManager.removeCustomService(context, "MyWiki")
        services = PinkServiceStatusManager.customServices.value
        assertTrue(services.isEmpty())
    }

    @Test
    fun testTrafficShaperMssRecommendation() {
        TrafficShaper.reset(50L)
        assertEquals(1440, TrafficShaper.getRecommendedMss())

        repeat(8) {
            TrafficShaper.updateRtt(600L)
        }
        assertTrue(TrafficShaper.getAvgRtt() > 300L)
        assertEquals(1200, TrafficShaper.getRecommendedMss())
    }

    @Test
    fun testBenchmarkManagerInitialStateAndStop() {
        assertFalse(BenchmarkManager.isRunning.value)
        assertEquals(0f, BenchmarkManager.progress.value, 0.001f)
        
        BenchmarkManager.stopBenchmark()
        assertFalse(BenchmarkManager.isRunning.value)
    }

    @Test
    fun testDiagnosticManagerLog() {
        BypassConfig.isDiagnosticMode = true
        DiagnosticManager.logDiagnostic("TEST", "Diagnostic test message")
        assertTrue(ProxyStats.recoveryLog.value.any { it.contains("Diagnostic test message") })
    }

    @Test
    fun testStabilityAnalyzerMetricsCalculation() {
        StabilityAnalyzer.reset()
        assertEquals(100, StabilityAnalyzer.stabilityScore.value)
        assertEquals(100, StabilityAnalyzer.successRate.value)
        assertEquals(0, StabilityAnalyzer.censorshipIntensity.value)

        // Record failure
        StabilityAnalyzer.recordEvent(isFailure = true, transport = com.aistudio.pinkproxy.fresh.TransportType.TCP)
        assertTrue(StabilityAnalyzer.successRate.value < 100)
        assertTrue(StabilityAnalyzer.censorshipIntensity.value > 0)
        assertTrue(StabilityAnalyzer.stabilityScore.value < 100)

        // Record success with RTT
        StabilityAnalyzer.recordEvent(isFailure = false, rtt = 120L, transport = com.aistudio.pinkproxy.fresh.TransportType.TCP)
        assertEquals(120L, StabilityAnalyzer.lastLatency.value)

        // Test signal quality update
        StabilityAnalyzer.updateSignalQuality(
            successRate = 90,
            stabilityScore = 80,
            censorshipIntensity = 10,
            isPanicMode = false
        )
        assertTrue(StabilityAnalyzer.signalQuality.value in 50..100)

        // Record DPI event
        StabilityAnalyzer.recordDpi(DpiType.TCP_RESET)
        assertEquals(DpiType.TCP_RESET, StabilityAnalyzer.currentDpiType.value)
        assertEquals(1, StabilityAnalyzer.dpiEventHistory.value.size)
    }
}
