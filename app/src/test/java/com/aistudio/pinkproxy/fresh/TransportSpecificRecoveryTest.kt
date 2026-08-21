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
class TransportSpecificRecoveryTest {

    @Before
    fun setUp() {
        StabilityAnalyzer.reset()
        BypassConfig.setPanicMode(false)
        BypassConfig.setMtu(1400)
    }

    @Test
    fun testDnsFailureDoesNotDisruptTcpBypassStrategy() = runTest {
        val initialTcpStrategy = BypassStrategy.TLS_REC_SPLIT
        BypassConfig.setGlobalStrategy(initialTcpStrategy)

        // Trigger DNS failure
        RecoveryStateMachine.handleSignal(RecoverySignal.DnsFailure(domain = "example.com", isPoisoned = false))
        
        // DNS failure should escalate without resetting TCP bypass
        assertEquals(initialTcpStrategy, BypassConfig.strategy.value)
    }

    @Test
    fun testTcpStallSelectsTcpOnlyCandidate() = runTest {
        RecoveryStateMachine.start(this)
        
        RecoveryStateMachine.handleSignal(
            RecoverySignal.TcpStall(
                host = "rutracker.org",
                strategy = BypassStrategy.DIRECT,
                transport = TransportType.TCP
            )
        )

        val newStrategy = BypassConfig.strategy.value
        assertTrue(
            "Selected strategy for TCP stall must be TCP compatible",
            DpiStrategySelector.isFamilyCompatible(newStrategy.family, TransportType.TCP)
        )
    }

    @Test
    fun testUdpDpiBlockSelectsUdpOnlyCandidate() = runTest {
        RecoveryStateMachine.start(this)
        
        RecoveryStateMachine.handleSignal(
            RecoverySignal.DpiDetected(
                type = DpiType.UDP_BLOCK,
                host = "discord.gg",
                transport = TransportType.UDP
            )
        )

        val newStrategy = BypassConfig.strategy.value
        assertTrue(
            "Selected strategy for UDP block must be UDP compatible",
            DpiStrategySelector.isFamilyCompatible(newStrategy.family, TransportType.UDP)
        )
    }

    @Test
    fun testNetworkLostInitiatesProbingState() = runTest {
        RecoveryStateMachine.start(this)
        
        RecoveryStateMachine.handleSignal(RecoverySignal.NetworkLost("WIFI_TO_CELLULAR"))
        assertEquals(RecoveryState.PROBING, RecoveryStateMachine.currentState.value)
    }
}
