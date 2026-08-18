package com.aistudio.pinkproxy.fresh

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class RuntimeCoordinatorTest {

    private lateinit var context: Context

    @Before
    fun setup() {
        context = ApplicationProvider.getApplicationContext()
        BypassConfig.clearScores(context)
        DpiEngine.resetStrategyScoresForNetworkChange()
    }

    @Test
    fun testInitializationAndShutdown() = runBlocking {
        RuntimeCoordinator.initialize(context)
        // Check engine state can receive signals
        RuntimeCoordinator.transitionGlobalStrategy(
            newStrategy = BypassStrategy.TLS_SNI_EXT_MANGLE,
            transport = TransportType.TCP,
            reason = "Test Transition"
        )
        RuntimeCoordinator.shutdown(context)
        assertNotNull(BypassConfig.strategy.value)
    }

    @Test
    fun testCentralizedRecoverySignalPublishing() = runBlocking {
        RecoveryStateMachine.start(this)
        
        // Post signal through RuntimeCoordinator
        RuntimeCoordinator.publishRecoverySignal(
            RecoverySignal.DpiDetected(DpiType.TLS_SNI_BLOCK, "test.youtube.com", TransportType.TCP)
        )
        
        // Ensure state machine handled event gracefully
        assertNotNull(RecoveryStateMachine.currentState.value)
        RecoveryStateMachine.stop()
    }
}
