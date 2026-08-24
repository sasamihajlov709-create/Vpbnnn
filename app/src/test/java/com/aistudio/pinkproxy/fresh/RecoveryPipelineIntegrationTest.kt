package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class RecoveryPipelineIntegrationTest {

    @Before
    fun setUp() {
        StabilityAnalyzer.reset()
        BypassConfig.setPanicMode(false)
        BypassConfig.setMtu(1400)
    }

    @Test
    fun testRecoveryManagerEventForwardingToStateMachine() = runTest {
        RecoveryStateMachine.start(this)

        // Trigger DPI detected event from RecoveryManager
        val stallJob = RecoveryManager.handleEvent(RecoveryEvent.TCP_STALL, "TCP socket stalled on test host")
        stallJob.join()
        assertEquals(RecoveryState.DEGRADED, RecoveryStateMachine.currentState.value)
        assertTrue(BypassConfig.currentMtu.value <= 1400)

        // Trigger manual recalibration
        val resetJob = RecoveryManager.recalibrateEverything()
        resetJob.join()
        assertEquals(RecoveryState.IDLE, RecoveryStateMachine.currentState.value)
        assertFalse(BypassConfig.isPanicMode)
    }

    @Test
    fun testDpiAnalyzerFingerprintPolicyConvergence() {
        // Feed various DPI events
        DpiAnalyzer.recordEvent(DpiType.TLS_SNI_BLOCK, com.aistudio.pinkproxy.fresh.TransportType.TCP)
        DpiAnalyzer.recordEvent(DpiType.TCP_RESET, com.aistudio.pinkproxy.fresh.TransportType.TCP)
        
        val fingerprint = DpiAnalyzer.getCensorshipFingerprint(com.aistudio.pinkproxy.fresh.TransportType.TCP)
        assertTrue(fingerprint.rstRate > 0.0 || fingerprint.sniBlockRate > 0.0)

        val decision = DpiPolicyEngine.evaluatePolicy(transport = com.aistudio.pinkproxy.fresh.TransportType.TCP,
            fingerprint = fingerprint,
            globalSuccessRate = 85.0,
            totalObservations = 20
        )
        assertNotNull(decision)
        assertTrue(decision.calculatedStability > 0)
    }
}
