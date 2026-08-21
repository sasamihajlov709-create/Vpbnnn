package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.net.InetAddress

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class Stage4PolicyAndTransportIntegrationTest {

    @Before
    fun setUp() {
        DpiPolicyEngine.resetAllEngineStates()
        UdpTransportHandler.clearBuffers()
    }

    @Test
    fun testDpiPolicyEvaluationForDifferentTransports() {
        val severeTcpFingerprint = DpiAnalyzer.CensorshipFingerprint(
            rstRate = 0.8,
            sniBlockRate = 0.6,
            udpBlockRate = 0.0,
            timeoutRate = 0.4,
            stallRate = 0.5,
            jitter = 700.0,
            intensity = 60,
            transport = TransportType.TCP
        )

        val tcpDecision = DpiPolicyEngine.evaluatePolicy(
            fingerprint = severeTcpFingerprint,
            globalSuccessRate = 10.0,
            totalObservations = 25,
            transport = TransportType.TCP
        )

        assertTrue("High RST and SNI blocks on TCP should escalate intensity", tcpDecision.targetIntensity > 50)
        assertTrue("Severe failure should trigger panic mode", tcpDecision.shouldEnterPanic)
        assertTrue("High jitter should boost adaptive & timing families", tcpDecision.familyBoosts.contains(StrategyFamily.ADAPTIVE))
        assertTrue("High jitter should boost timing family", tcpDecision.familyBoosts.contains(StrategyFamily.TIMING))
        assertEquals(TransportType.TCP, tcpDecision.affectedTransport)

        val severeUdpFingerprint = DpiAnalyzer.CensorshipFingerprint(
            rstRate = 0.0,
            sniBlockRate = 0.0,
            udpBlockRate = 0.9,
            timeoutRate = 0.5,
            stallRate = 0.0,
            jitter = 100.0,
            intensity = 70,
            transport = TransportType.UDP
        )

        val udpDecision = DpiPolicyEngine.evaluatePolicy(
            fingerprint = severeUdpFingerprint,
            globalSuccessRate = 8.0,
            totalObservations = 22,
            transport = TransportType.UDP
        )

        assertTrue("UDP block rate of 0.9 should result in high intensity", udpDecision.targetIntensity >= 70)
        assertEquals(TransportType.UDP, udpDecision.affectedTransport)
    }

    @Test
    fun testQuicFilteringHeuristics() {
        // STUN packet (Magic cookie 0x21 0x12 0xA4 0x42 at offset 4)
        val stunPayload = ByteArray(24).apply {
            this[0] = 0x00
            this[1] = 0x01 // Binding Request
            this[4] = 0x21.toByte()
            this[5] = 0x12.toByte()
            this[6] = 0xA4.toByte()
            this[7] = 0x42.toByte()
        }
        assertTrue("STUN packet should be recognized", UdpTransportHandler.isStunPacket(stunPayload))
        assertFalse(
            "STUN packet must NEVER be blocked even in AUTO mode",
            UdpTransportHandler.shouldBlockQuicForHost("discord.gg", 50000, stunPayload)
        )

        // QUIC Initial packet (Long header flag 0x80 or 0x40)
        val quicInitial = ByteArray(20).apply {
            this[0] = 0xC0.toByte() // Long header Initial
        }

        BypassConfig.setQuicBypassMode(QuicBypassMode.FORCE_BLOCK)
        assertTrue(
            "FORCE_BLOCK should block QUIC initial",
            UdpTransportHandler.shouldBlockQuicForHost("example.com", 443, quicInitial)
        )

        BypassConfig.setQuicBypassMode(QuicBypassMode.FORCE_ALLOW)
        assertFalse(
            "FORCE_ALLOW should never block QUIC initial",
            UdpTransportHandler.shouldBlockQuicForHost("googlevideo.com", 443, quicInitial)
        )

        // AUTO mode
        BypassConfig.setQuicBypassMode(QuicBypassMode.AUTO)
        assertTrue(
            "AUTO mode should fast-block YouTube CDN video streams to trigger instant TCP fallback",
            UdpTransportHandler.shouldBlockQuicForHost("rr1---sn-4g5edn6e.googlevideo.com", 443, quicInitial)
        )
    }

    @Test
    fun testStrategyExecutionRegistryCoverageAndIntegrity() {
        for (strategy in BypassStrategy.entries) {
            assertTrue(
                "Strategy $strategy must be registered in StrategyExecutionRegistry",
                StrategyExecutionRegistry.isActuallyImplemented(strategy)
            )

            val executorType = StrategyExecutionRegistry.getExecutorType(strategy)
            assertNotNull("Strategy $strategy must map to a non-null ExecutorType", executorType)

            val executor = StrategyExecutionRegistry.getExecutor(strategy)
            assertNotNull("Strategy $strategy must resolve to a valid StrategyExecutor instance", executor)
            assertTrue("Executor must explicitly declare support for $strategy", executor.supportsStrategy(strategy))
        }
    }

    @Test
    fun testRuntimeCoordinatorContextualRotation() = runTest {
        val selectedTcp = RuntimeCoordinator.rotateGlobalStrategy(
            transport = TransportType.TCP,
            reason = "Stage4 Test",
            category = HostCategory.STREAMING,
            profileId = "test_profile"
        )
        assertNotNull(selectedTcp)
        assertTrue(StrategyExecutionRegistry.isExecutorSupported(selectedTcp, TransportType.TCP))

        val selectedUdp = RuntimeCoordinator.rotateGlobalStrategy(
            transport = TransportType.UDP,
            reason = "Stage4 Test UDP",
            category = HostCategory.MESSENGER,
            profileId = "test_profile"
        )
        assertNotNull(selectedUdp)
        assertTrue(StrategyExecutionRegistry.isExecutorSupported(selectedUdp, TransportType.UDP))
    }
}
