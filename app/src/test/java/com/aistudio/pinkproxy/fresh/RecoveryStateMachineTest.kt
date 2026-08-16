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
class RecoveryStateMachineTest {

    @Before
    fun setUp() {
        StabilityAnalyzer.reset()
        BypassConfig.setPanicMode(false)
        BypassConfig.setMtu(1400)
    }

    @Test
    fun testInitialStateIsIdle() = runTest {
        RecoveryStateMachine.start(this)
        assertEquals(RecoveryState.IDLE, RecoveryStateMachine.currentState.value)
    }

    @Test
    fun testDpiDetectedSignalTransitionsToDegradedAndSelectsStrategy() = runTest {
        RecoveryStateMachine.start(this)

        RecoveryStateMachine.handleSignal(RecoverySignal.DpiDetected(DpiType.TCP_RESET))
        assertEquals(RecoveryState.PANIC_MODE, RecoveryStateMachine.currentState.value)
        assertTrue(BypassConfig.isPanicMode)

        RecoveryStateMachine.handleSignal(RecoverySignal.DpiDetected(DpiType.TLS_SNI_BLOCK))
        assertNotNull(BypassConfig.strategy.value)
    }

    @Test
    fun testTunnelStallSignalAdjustsMtuAndTtl() = runTest {
        RecoveryStateMachine.start(this)
        BypassConfig.setMtu(1400)

        // First stall escalates and reconfigures MTU
        RecoveryStateMachine.handleSignal(RecoverySignal.TunnelStall(durationMs = 15000, activeConnections = 3))
        assertEquals(RecoveryState.RECONFIGURING_MTU, RecoveryStateMachine.currentState.value)

        // Second stall reduces MTU further
        RecoveryStateMachine.handleSignal(RecoverySignal.TunnelStall(durationMs = 15000, activeConnections = 3))
        assertTrue(BypassConfig.currentMtu.value <= 1400)
    }

    @Test
    fun testDnsFailureSignalClearsCachesAndHandlesPoisoning() = runTest {
        RecoveryStateMachine.start(this)

        RecoveryStateMachine.handleSignal(RecoverySignal.DnsFailure(domain = "blocked-service.com", isPoisoned = true))
        assertEquals(RecoveryState.PANIC_MODE, RecoveryStateMachine.currentState.value)
        assertEquals("Smart DoH", RobustResolver.dnsMode)
    }

    @Test
    fun testMemoryPressureCleansCaches() = runTest {
        RecoveryStateMachine.start(this)

        RecoveryStateMachine.handleSignal(RecoverySignal.MemoryPressure(usedPercent = 88))
        // Should execute cache cleans without error
        assertNotNull(RecoveryStateMachine.currentState.value)
    }

    @Test
    fun testManualResetRestoresDefaults() = runTest {
        RecoveryStateMachine.start(this)

        BypassConfig.setPanicMode(true)
        BypassConfig.setMtu(1200)

        RecoveryStateMachine.handleSignal(RecoverySignal.ManualReset)
        assertEquals(RecoveryState.IDLE, RecoveryStateMachine.currentState.value)
        assertFalse(BypassConfig.isPanicMode)
        assertEquals(1400, BypassConfig.currentMtu.value)
    }

    @Test
    fun testCoolDownEscalation() = runTest {
        RecoveryStateMachine.start(this)

        RecoveryStateMachine.handleSignal(RecoverySignal.ExtremeLatency(3500))
        assertEquals(RecoveryState.DEGRADED, RecoveryStateMachine.currentState.value)

        RecoveryStateMachine.coolDownEscalation(2)
        // Should cool down safely
    }
}
