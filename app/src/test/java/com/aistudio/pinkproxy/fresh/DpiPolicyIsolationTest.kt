package com.aistudio.pinkproxy.fresh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking

class DpiPolicyIsolationTest {

    @Before
    fun setup() {
        StrategyStateRepository.clearProfileState("default")
        DpiPolicyEngine.transportPolicies.values.forEach { it.calculatedIntensity = 0 }
        ProxyStats.updateCensorshipIntensity(0)
    }

    @Test
    fun testGlobalMetricsNotOverwrittenSequentially() = runBlocking {
        // TCP is heavily censored
        val tcpDecision = DpiPolicyEngine.evaluatePolicy(
            fingerprint = DpiAnalyzer.CensorshipFingerprint(rstRate = 0.9, sniBlockRate = 0.9, udpBlockRate = 0.0, dnsBlockRate = 0.0, timeoutRate = 0.0, stallRate = 0.0, jitter = 0.0, intensity = 0, transport = TransportType.TCP),
            globalSuccessRate = 5.0,
            totalObservations = 50,
            transport = TransportType.TCP
        )
        DpiPolicyEngine.applyPolicyDecision(tcpDecision)
        
        // At this point, the UI shouldn't update yet because we decoupled it
        // However, the policy state for TCP should be high
        val tcpIntensity = DpiPolicyEngine.transportPolicies[TransportType.TCP]?.calculatedIntensity ?: 0
        assertTrue("tcpIntensity was $tcpIntensity", tcpIntensity >= 80)

        // UDP is perfectly fine
        val udpDecision = DpiPolicyEngine.evaluatePolicy(
            fingerprint = DpiAnalyzer.CensorshipFingerprint(rstRate = 0.0, sniBlockRate = 0.0, udpBlockRate = 0.0, dnsBlockRate = 0.0, timeoutRate = 0.0, stallRate = 0.0, jitter = 0.0, intensity = 0, transport = TransportType.UDP),
            globalSuccessRate = 100.0,
            totalObservations = 50,
            transport = TransportType.UDP
        )
        DpiPolicyEngine.applyPolicyDecision(udpDecision)

        val udpIntensity = DpiPolicyEngine.transportPolicies[TransportType.UDP]?.calculatedIntensity ?: 0
        assertEquals("udpIntensity was $udpIntensity", 0, udpIntensity)

        // Now aggregate globally
        DpiPolicyEngine.aggregateGlobalMetrics()

        // Global intensity should be a weighted average (TCP * 0.5 + UDP * 0.3 + DNS * 0.2)
        // If TCP is ~100 and UDP is 0, global should be around 50
        val globalCensorship = ProxyStats.censorshipIntensity.first()
        assertTrue("Global intensity should be blended, got $globalCensorship", globalCensorship in 30..60)
    }
}
