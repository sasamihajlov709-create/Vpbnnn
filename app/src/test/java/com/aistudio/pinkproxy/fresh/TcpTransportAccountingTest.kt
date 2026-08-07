package com.aistudio.pinkproxy.fresh

import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class TcpTransportAccountingTest {

    @Before
    fun setUp() {
        ProxyStats.clearCensorshipHistory()
    }

    @Test
    fun `unregisterFlow with success updates flow status`() {
        val sessionId = "test_flow_success"
        ProxyStats.registerFlow(sessionId, "example.com", "TCP", BypassStrategy.SNI_SPLIT)
        
        ProxyStats.unregisterFlow(sessionId, success = true)

        assertEquals(0, ProxyStats.censorshipIntensity.value)
    }

    @Test
    fun `unregisterFlow with failure records error event`() {
        val initialErrors = ProxyStats.errors.value
        val sessionId = "test_flow_fail"
        ProxyStats.registerFlow(sessionId, "fail.com", "TCP", BypassStrategy.TCP_OOB_DESYNC)

        ProxyStats.unregisterFlow(sessionId, success = false)

        assertEquals(initialErrors + 1L, ProxyStats.errors.value)
    }

    @Test
    fun `StabilityAnalyzer metrics correctly respond to state updates`() {
        ProxyStats.updateCensorshipIntensity(75)
        assertEquals(75, ProxyStats.censorshipIntensity.value)

        ProxyStats.updateStabilityScore(88)
        assertEquals(88, ProxyStats.stabilityScore.value)
    }
}
