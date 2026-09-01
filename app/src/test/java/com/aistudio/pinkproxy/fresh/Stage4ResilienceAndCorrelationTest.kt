package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket

class Stage4ResilienceAndCorrelationTest {

    @Before
    fun setup() {
        StrategyStateRepository.clearProfileState("default")
        BypassConfig.isAutoTuning = true
        BypassConfig.autoTuningMode = AutoTuningMode.STABLE
        UdpAssociationTable.clear()
    }

    @Test
    fun testUdpCorrelationKeyExtractionDns() {
        // Build a mock DNS query payload with Transaction ID 0x1234
        val dnsQuery = ByteArray(32) { 0 }
        dnsQuery[0] = 0x12.toByte()
        dnsQuery[1] = 0x34.toByte()
        dnsQuery[2] = 0x01.toByte() // Standard query flag

        val key = UdpTransportHandler.extractCorrelationKey(dnsQuery, 0, dnsQuery.size, 53)
        assertEquals("dns:4660", key) // 0x1234 == 4660
    }

    @Test
    fun testUdpCorrelationKeyExtractionStun() {
        // Build a mock STUN Binding Request payload
        val stunPayload = ByteArray(24) { 0 }
        stunPayload[0] = 0x00.toByte()
        stunPayload[1] = 0x01.toByte() // Binding Request
        stunPayload[4] = 0x21.toByte()
        stunPayload[5] = 0x12.toByte()
        stunPayload[6] = 0xA4.toByte()
        stunPayload[7] = 0x42.toByte() // Magic Cookie
        // Transaction ID (12 bytes)
        for (i in 8 until 20) {
            stunPayload[i] = (i * 2).toByte()
        }

        val key = UdpTransportHandler.extractCorrelationKey(stunPayload, 0, stunPayload.size, 3478)
        assertNotNull(key)
        assertTrue(key!!.startsWith("stun:"))
    }

    @Test
    fun testUdpCorrelatedProbeMatchingAndOutOfOrderResolution() {
        val clientIp = InetAddress.getByName("127.0.0.1")
        val session = UdpAssociationTable.getOrCreateSession(
            sessionId = "test-session",
            clientAddress = clientIp,
            clientPort = 44556,
            destinationHost = "8.8.8.8",
            destinationPort = 53,
            strategy = BypassStrategy.DIRECT
        )

        val probe1 = UdpPendingProbe(
            host = "8.8.8.8",
            strategy = BypassStrategy.UDP_QUIC_PAD,
            sentTime = System.currentTimeMillis() - 200,
            correlationKey = "dns:1001"
        )
        val probe2 = UdpPendingProbe(
            host = "8.8.8.8",
            strategy = BypassStrategy.UDP_HEARTBEAT,
            sentTime = System.currentTimeMillis() - 100,
            correlationKey = "dns:1002"
        )

        // Enqueue probe 1 then probe 2
        session.addProbe(probe1)
        session.addProbe(probe2)

        // Simulate receiving response for probe 2 FIRST (out-of-order UDP response)
        val matchedFor2 = session.popMatchingProbe("dns:1002")
        assertNotNull(matchedFor2)
        assertEquals(BypassStrategy.UDP_HEARTBEAT, matchedFor2?.strategy)

        // Then receive response for probe 1
        val matchedFor1 = session.popMatchingProbe("dns:1001")
        assertNotNull(matchedFor1)
        assertEquals(BypassStrategy.UDP_QUIC_PAD, matchedFor1?.strategy)

        // Queue should now be empty
        assertNull(session.popMatchingProbe("dns:1001"))
        assertNull(session.popProbe())
    }

    @Test
    fun testUdpProbeExpirationCleanup() {
        val clientIp = InetAddress.getByName("127.0.0.1")
        val session = UdpAssociationTable.getOrCreateSession(
            sessionId = "expired-session",
            clientAddress = clientIp,
            clientPort = 44557,
            destinationHost = "1.1.1.1",
            destinationPort = 53,
            strategy = BypassStrategy.DIRECT
        )

        val expiredProbe = UdpPendingProbe(
            host = "1.1.1.1",
            strategy = BypassStrategy.UDP_QUIC_PAD,
            sentTime = System.currentTimeMillis() - 20_000L, // 20s ago (> 10s max age)
            correlationKey = "dns:9999"
        )
        session.addProbe(expiredProbe)

        // Calling popMatchingProbe after expiration should prune the expired probe and return null
        val matched = session.popMatchingProbe("dns:9999")
        assertNull(matched)
    }

    @Test
    fun testAutoTuningModeStablePrioritizesDeviceVerified() {
        val context = CandidateEngine.SelectionContext(
            transport = TransportType.TCP,
            profileId = "default",
            host = "example.com",
            category = HostCategory.SEARCH
        )

        val verifiedStrategy = BypassStrategy.TLS_RECORD_FRAGMENTATION
        val unverifiedStrategy = BypassStrategy.TCP_PULSE_FRAG

        assertTrue(verifiedStrategy.validationStatus == ValidationStatus.DEVICE_VERIFIED)

        // In STABLE mode, verifiedStrategy should rank higher
        BypassConfig.autoTuningMode = AutoTuningMode.STABLE
        val stableRanked = CandidateEngine.rankCandidatesBayesian(
            listOf(unverifiedStrategy, verifiedStrategy),
            context
        )
        assertEquals(verifiedStrategy, stableRanked.first())

        // In EXPLORATION mode, verify candidate selection still functions cleanly
        BypassConfig.autoTuningMode = AutoTuningMode.EXPLORATION
        val explorationRanked = CandidateEngine.rankCandidatesBayesian(
            listOf(unverifiedStrategy, verifiedStrategy),
            context
        )
        assertNotNull(explorationRanked)
        assertEquals(2, explorationRanked.size)
    }

    @Test
    fun testProtectedSocketFactorySafeCreationWithoutVpn() {
        // When VPN service is not active (null), creation should safely succeed without throwing
        val socket: Socket = ProtectedSocketFactory.createProtectedSocket(null)
        assertNotNull(socket)
        assertFalse(socket.isClosed)
        socket.close()

        val datagramSocket: DatagramSocket = ProtectedSocketFactory.createProtectedDatagramSocket(null)
        assertNotNull(datagramSocket)
        assertFalse(datagramSocket.isClosed)
        datagramSocket.close()
    }
}
