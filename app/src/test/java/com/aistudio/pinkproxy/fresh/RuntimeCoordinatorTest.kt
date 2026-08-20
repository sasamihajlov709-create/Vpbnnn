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
class RuntimeCoordinatorTest {

    @Before
    fun setUp() {
        BypassConfig.setPanicMode(false)
        BypassConfig.setMtu(1400)
    }

    @Test
    fun testTransitionValidTcpStrategy() = runTest {
        val strategy = BypassStrategy.TLS_REC_SPLIT
        val result = RuntimeCoordinator.applyStrategyTransition(strategy, TransportType.TCP, "Test Valid TCP")
        
        assertTrue("Strategy transition must succeed for compatible strategy and transport", result)
        assertEquals(strategy, BypassConfig.strategy.value)
    }

    @Test
    fun testTransitionIncompatibleStrategyFallsBackSafely() = runTest {
        // HTTP Strategy applied to UDP transport is incompatible
        val httpStrategy = BypassStrategy.HTTP_HOST_SPACE
        val result = RuntimeCoordinator.applyStrategyTransition(httpStrategy, TransportType.UDP, "Test Incompatible UDP")

        assertTrue("Transition should complete with fallback", result)
        val current = BypassConfig.strategy.value
        assertTrue(
            "State must fall back to a valid UDP-compatible strategy",
            DpiStrategySelector.isFamilyCompatible(current.family, TransportType.UDP)
        )
    }

    @Test
    fun testRotateGlobalStrategyUnderCoordinator() = runTest {
        val selected = RuntimeCoordinator.rotateGlobalStrategy(TransportType.UDP, "Test UDP Rotation")
        
        assertTrue(
            "Rotated strategy must be UDP compatible",
            DpiStrategySelector.isFamilyCompatible(selected.family, TransportType.UDP)
        )
        assertEquals(selected, BypassConfig.strategy.value)
    }

    @Test
    fun testRequestGlobalStrategyRotationAsynchronous() = runTest {
        val job = RuntimeCoordinator.requestGlobalStrategyRotation(TransportType.TCP, "Async Test Rotation")
        job.join()
        assertNotNull(BypassConfig.strategy.value)
        assertTrue(DpiStrategySelector.isFamilyCompatible(BypassConfig.strategy.value.family, TransportType.TCP))
    }

    @Test
    fun testPublishRecoverySignal() {
        val signal = RecoverySignal.DpiDetected(DpiType.TCP_RESET, "test.org", TransportType.TCP)
        RuntimeCoordinator.publishRecoverySignal(signal)
        assertNotNull(RecoveryStateMachine.currentState.value)
    }

    @Test
    fun testInitializeAndShutdownIdempotence() = runTest {
        val context = org.robolectric.RuntimeEnvironment.getApplication()
        RuntimeCoordinator.initialize(context).join()
        assertTrue(RuntimeCoordinator.isEngineActive.value)

        // Multiple initialize calls should be safely idempotent
        RuntimeCoordinator.initialize(context).join()
        assertTrue(RuntimeCoordinator.isEngineActive.value)

        // Shutdown cleanly cancels session
        RuntimeCoordinator.shutdown(context).join()
        assertFalse(RuntimeCoordinator.isEngineActive.value)
    }
}
