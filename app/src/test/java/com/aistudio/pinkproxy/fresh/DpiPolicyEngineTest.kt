package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class DpiPolicyEngineTest {

    @Before
    fun setUp() {
        StabilityAnalyzer.reset()
        BypassConfig.setPanicMode(false)
        BypassConfig.setMtu(1400)
    }

    @Test
    fun testSevereAnomalyTriggersPanicAndFamilyBoosts() {
        val severeFingerprint = DpiAnalyzer.CensorshipFingerprint(
            rstRate = 0.6,
            sniBlockRate = 0.5,
            udpBlockRate = 0.4,
            timeoutRate = 0.5,
            stallRate = 0.4,
            jitter = 750.0,
            intensity = 80
        )

        val decision = DpiPolicyEngine.evaluatePolicy(
            fingerprint = severeFingerprint,
            globalSuccessRate = 10.0,
            totalObservations = 50
        )

        assertTrue("Severe anomaly should trigger panic mode", decision.shouldEnterPanic)
        assertTrue("Calculated stability should be low", decision.calculatedStability < 50)
        assertNotNull("MTU should be reduced on high timeouts/stalls", decision.recommendedMtu)
        assertTrue("Adaptive family should be boosted on high jitter", decision.familyBoosts.contains(StrategyFamily.ADAPTIVE))
        assertTrue("Timing family should be boosted", decision.familyBoosts.contains(StrategyFamily.TIMING))

        DpiPolicyEngine.applyPolicyDecision(decision)
        assertTrue("Panic mode should be active in BypassConfig", BypassConfig.isPanicMode)
        assertTrue("Censorship intensity should increase", ProxyStats.censorshipIntensity.value > 50)
    }

    @Test
    fun testCleanNetworkIncreasesMtuAndStability() {
        val cleanFingerprint = DpiAnalyzer.CensorshipFingerprint(
            rstRate = 0.0,
            sniBlockRate = 0.0,
            udpBlockRate = 0.0,
            timeoutRate = 0.0,
            stallRate = 0.0,
            jitter = 15.0,
            intensity = 10
        )

        BypassConfig.setMtu(1300)
        val decision = DpiPolicyEngine.evaluatePolicy(
            fingerprint = cleanFingerprint,
            globalSuccessRate = 98.0,
            totalObservations = 100
        )

        assertFalse("Clean network should not trigger panic", decision.shouldEnterPanic)
        assertTrue("Calculated stability should be high", decision.calculatedStability >= 90)
        assertEquals(1316, decision.recommendedMtu)

        DpiPolicyEngine.applyPolicyDecision(decision)
        assertEquals(1316, BypassConfig.currentMtu.value)
    }

    @Test
    fun testDpiEventDiagnosisBoosts() {
        DpiPolicyEngine.onDpiEventDiagnosed(DpiType.TLS_SNI_BLOCK)
        DpiPolicyEngine.onDpiEventDiagnosed(DpiType.UDP_BLOCK)
        DpiPolicyEngine.onDpiEventDiagnosed(DpiType.TCP_RESET)
        // Should execute without errors and boost appropriate families
    }

    @Test
    fun testResetAllEngineStates() {
        DpiEngine.strategyScores[HostCategory.OTHER]?.get(BypassStrategy.SNI_SPLIT)?.set(400)
        DpiEngine.circuitBreakers[BypassStrategy.SNI_SPLIT] = System.currentTimeMillis() + 10000L

        DpiPolicyEngine.resetAllEngineStates()

        assertEquals(100, DpiEngine.strategyScores[HostCategory.OTHER]?.get(BypassStrategy.SNI_SPLIT)?.get())
        assertTrue(DpiEngine.circuitBreakers.isEmpty())
    }
}
