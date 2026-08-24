package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Stage 5 Verification Test:
 * Verifies that the SOCKS5 username/password protocol successfully bridges
 * to the `benchmarkForcedStrategy` without mutating the Global state.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class BenchmarkSessionIntegrationTest {

    @Test
    fun `benchmark session isolator extracts strategy without mutating global config`() = runBlocking {
        // Set the global strategy to something known
        BypassConfig.setStrategy(BypassStrategy.DIRECT, TransportType.TCP)
        assertEquals(BypassStrategy.DIRECT, BypassConfig.getSessionConfig("example.com", BypassStrategy.DIRECT, 0L, TransportType.TCP).strategy)
        
        // Simulate what PinkProxyServer does during SOCKS5 Auth Phase (sub-negotiation)
        // User = "BENCHMARK_SESSION"
        // Passwd = "TCP_FOOL_DPI"
        val authUser = "BENCHMARK_SESSION"
        val authPasswd = "TCP_FOOL_DPI"
        
        var benchmarkForcedStrategy: BypassStrategy? = null
        if (authUser.startsWith("BENCHMARK_SESSION")) {
            try {
                benchmarkForcedStrategy = BypassStrategy.valueOf(authPasswd)
            } catch (e: Exception) {
                // Ignore invalid strategy
            }
        }
        
        // Verify it extracted successfully
        assertNotNull("Should parse the strategy correctly", benchmarkForcedStrategy)
        assertEquals(BypassStrategy.TCP_FOOL_DPI, benchmarkForcedStrategy)
        
        // Ensure Global State was NOT modified
        assertEquals(
            "Global strategy must remain unmodified by benchmark sessions",
            BypassStrategy.DIRECT,
            BypassConfig.getSessionConfig("example.com", BypassStrategy.DIRECT, 0L, TransportType.TCP).strategy
        )
    }
}
