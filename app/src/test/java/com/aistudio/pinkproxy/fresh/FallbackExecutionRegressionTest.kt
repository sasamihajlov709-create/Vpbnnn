package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.IOException

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], manifest = Config.NONE)
class FallbackExecutionRegressionTest {

    @Before
    fun setup() {
        StrategyStateRepository.clearProfileState("DEFAULT")
    }

    @Test
    fun `test BLOCK_TRAFFIC executes safely via Direct executor and throws expected traffic blocked exception`() = runTest {
        // Arrange
        val strategy = BypassStrategy.BLOCK_TRAFFIC
        
        // Assert Policy Gate allows it since it's the catch-all fallback
        val ctx = CandidateEngine.SelectionContext(TransportType.TCP)
        assertTrue(StrategyPolicyGate.isAllowed(strategy, ctx))
        
        // Assert registry maps it
        assertTrue(StrategyExecutionRegistry.isExecutorSupported(strategy, TransportType.TCP))
        
        // Execute it and expect IOException for TCP
        var caughtException = false
        try {
            val socket = java.net.Socket()
            val output = java.io.ByteArrayOutputStream()
            val execCtx = TcpExecutionContext(
                socket = socket,
                output = output,
                data = ByteArray(0),
                length = 0,
                host = "test",
                strategy = strategy,
                config = SessionConfig(
                    strategy = strategy, 
                    frag1 = 0, 
                    delay1 = 0, 
                    fakeTtl = 0
                ),
                effectiveDelayMs = 0
            )
            StrategyExecutorDirect.executeTcp(execCtx)
        } catch (e: IOException) {
            caughtException = true
            assertEquals("Traffic explicitly blocked by policy", e.message)
        }
        
        assertTrue("Expected IOException to be thrown for BLOCK_TRAFFIC", caughtException)
    }
}
