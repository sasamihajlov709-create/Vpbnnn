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
@Config(manifest = Config.NONE)
class StrategyEscalationMatrixTest {

    @Before
    fun setup() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        BypassConfig.clearScores(context)
        DpiEngine.resetStrategyScoresForNetworkChange()
        DpiEngine.circuitBreakers.clear()
        DpiEngine.hostStrategyBlacklist.clear()
    }

    @Test
    fun testTcpResetEscalationPath() {
        // When SNI_SPLIT encounters active TCP RST, escalation should move towards TCP segment overlap / desync
        val next = StrategyEscalationMatrix.getEscalatedStrategy(
            failedStrategy = BypassStrategy.SNI_SPLIT,
            reason = FailureReason.TCP_RESET,
            transport = TransportType.TCP
        )
        assertNotNull("Next strategy on TCP reset must not be null", next)
        assertTrue(
            "Should escalate to TLS SNI fragment or deeper TCP overlap/desync",
            next == BypassStrategy.TLS_SNI_FRAGMENT || next == BypassStrategy.TCP_SEGMENT_OVERLAP
        )

        // When deeper in the chain, it should escalate towards TCP Combined Hybrid and Nuclear
        val hybridNext = StrategyEscalationMatrix.getEscalatedStrategy(
            failedStrategy = BypassStrategy.TCP_FAKE_FIN,
            reason = FailureReason.TCP_RESET,
            transport = TransportType.TCP
        )
        assertEquals(BypassStrategy.TCP_COMBINED_HYBRID, hybridNext)

        val nuclearNext = StrategyEscalationMatrix.getEscalatedStrategy(
            failedStrategy = BypassStrategy.TCP_COMBINED_HYBRID,
            reason = FailureReason.TCP_RESET,
            transport = TransportType.TCP
        )
        assertEquals(BypassStrategy.TCP_COMBINED_NUCLEAR, nuclearNext)
    }

    @Test
    fun testCensorshipStallEscalationPath() {
        // When stalling on SNI, escalation moves towards advanced Jitter / Extreme engines
        val next = StrategyEscalationMatrix.getEscalatedStrategy(
            failedStrategy = BypassStrategy.TLS_SNI_FRAGMENT,
            reason = FailureReason.CENSORSHIP_STALL,
            transport = TransportType.TCP
        )
        assertNotNull("Next strategy on stall must not be null", next)
        assertTrue(
            "Should escalate to Jitter Split, Chop or Extreme",
            next == BypassStrategy.TLS_SNI_JITTER_SPLIT || next == BypassStrategy.TLS_CLIENT_HELLO_CHOP || next == BypassStrategy.BYEBYEDPI_EXTREME || next == BypassStrategy.ZAPRET_EXTREME
        )
    }

    @Test
    fun testUdpDisruptionEscalationPath() {
        val next = StrategyEscalationMatrix.getEscalatedStrategy(
            failedStrategy = BypassStrategy.UDP_NOISE_CHAOS,
            reason = FailureReason.TIMEOUT,
            transport = TransportType.UDP
        )
        assertNotNull(next)
        assertTrue(
            "UDP failure should escalate to burst chaos or nuclear UDP",
            next == BypassStrategy.UDP_BURST_CHAOS || next == BypassStrategy.UDP_COMBINED_NUCLEAR || next == BypassStrategy.UDP_COMBINED_HYBRID
        )
    }

    @Test
    fun testCircuitBreakerBypassInEscalation() {
        val base = BypassStrategy.SNI_SPLIT
        val directNext = BypassStrategy.TLS_SNI_FRAGMENT

        // Place directNext under circuit breaker
        DpiEngine.circuitBreakers[directNext] = System.currentTimeMillis() + 600_000L

        val escalated = StrategyEscalationMatrix.getEscalatedStrategy(
            failedStrategy = base,
            reason = FailureReason.TCP_RESET,
            transport = TransportType.TCP
        )

        assertNotNull(escalated)
        assertNotEquals("Should skip strategy under circuit breaker", directNext, escalated)
    }

    @Test
    fun testHostBlacklistBypassInEscalation() {
        val host = "blocked-service.example.org"
        val base = BypassStrategy.SNI_SPLIT
        val directNext = BypassStrategy.TLS_SNI_FRAGMENT

        // Blacklist directNext for this host
        val hostMap = DpiEngine.hostStrategyBlacklist.getOrPut(host) { java.util.concurrent.ConcurrentHashMap() }
        hostMap[directNext] = System.currentTimeMillis() + 3_600_000L

        val escalated = StrategyEscalationMatrix.getEscalatedStrategy(
            failedStrategy = base,
            reason = FailureReason.TCP_RESET,
            transport = TransportType.TCP,
            host = host
        )

        assertNotNull(escalated)
        assertNotEquals("Should skip host-blacklisted strategy", directNext, escalated)
    }
}
