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
    fun testStableModeGatekeeperStrictlyFiltersUnverifiedCandidates() {
        val context = CandidateEngine.SelectionContext(
            transport = TransportType.TCP,
            profileId = "default",
            host = "example.com",
            category = HostCategory.SEARCH
        )

        val verifiedStrategy = BypassStrategy.TLS_RECORD_FRAGMENTATION
        val unverifiedStrategy = BypassStrategy.TCP_PULSE_FRAG

        BypassConfig.isAutoTuning = true
        BypassConfig.autoTuningMode = AutoTuningMode.STABLE

        // Unverified strategy with 0 observations MUST be filtered out by isEligible in STABLE mode
        assertFalse(CandidateEngine.isEligible(unverifiedStrategy, context))
        assertTrue(CandidateEngine.isEligible(verifiedStrategy, context))

        val eligibleStable = CandidateEngine.getEligibleCandidates(context, listOf(unverifiedStrategy, verifiedStrategy))
        assertEquals(listOf(verifiedStrategy), eligibleStable)

        // In EXPLORATION mode, unverified strategy is eligible
        BypassConfig.autoTuningMode = AutoTuningMode.EXPLORATION
        assertTrue(CandidateEngine.isEligible(unverifiedStrategy, context))
    }

    @Test
    fun testUdpStrictCorrelationRejectsMismatchedKeyWithoutPollFallback() {
        val clientIp = InetAddress.getByName("127.0.0.1")
        val session = UdpAssociationTable.getOrCreateSession(
            sessionId = "mismatch-session",
            clientAddress = clientIp,
            clientPort = 44558,
            destinationHost = "8.8.8.8",
            destinationPort = 53,
            strategy = BypassStrategy.DIRECT
        )

        val probe = UdpPendingProbe(
            host = "8.8.8.8",
            strategy = BypassStrategy.UDP_QUIC_PAD,
            sentTime = System.currentTimeMillis(),
            correlationKey = "dns:5555"
        )
        session.addProbe(probe)

        // If an incoming packet has unknown/unmatched key "dns:7777", it should NOT pop probe "dns:5555"
        val mismatched = session.popMatchingProbe("dns:7777")
        assertNull(mismatched)

        // The correct probe should still remain and be pop-able with its exact key
        val matched = session.popMatchingProbe("dns:5555")
        assertNotNull(matched)
        assertEquals("dns:5555", matched?.correlationKey)
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

    @Test
    fun testDnsResolutionFailureDoesNotPenalizeStrategyScore() {
        val strategy = BypassStrategy.TLS_RECORD_FRAGMENTATION
        val transport = TransportType.TCP
        val profileId = "default"
        val state = StrategyStateRepository.getStrategyState(strategy, transport, HostCategory.OTHER, profileId)
        
        val initialWeightedFailure = state.weightedFailure.get()

        val dnsFailObs = StrategyObservation(
            executedStrategy = strategy,
            transport = transport,
            quality = ObservationQuality.CONNECT_ONLY,
            profileId = profileId,
            success = false,
            failureReason = FailureReason.DNS_RESOLUTION_FAILED
        )

        state.recordObservation(dnsFailObs)

        // DNS resolution failure should increment failure count for telemetry, but apply 0 weight penalty to strategy rating
        assertEquals(initialWeightedFailure, state.weightedFailure.get())
    }

    @Test
    fun testUdpAssociationPrunesStaleSessionsSelectively() {
        val clientIp = InetAddress.getByName("127.0.0.1")
        val sessionActive = UdpAssociationTable.getOrCreateSession(
            sessionId = "active-socks",
            clientAddress = clientIp,
            clientPort = 50001,
            destinationHost = "1.1.1.1",
            destinationPort = 53,
            strategy = BypassStrategy.DIRECT
        )
        sessionActive.lastActivity = System.currentTimeMillis()

        val sessionStale = UdpAssociationTable.getOrCreateSession(
            sessionId = "stale-socks",
            clientAddress = clientIp,
            clientPort = 50002,
            destinationHost = "8.8.8.8",
            destinationPort = 53,
            strategy = BypassStrategy.DIRECT
        )
        sessionStale.lastActivity = System.currentTimeMillis() - 120_000L // 2 minutes old

        val pruned = UdpAssociationTable.cleanupExpiredSessions(maxIdleDurationMs = 60_000L)
        assertTrue(pruned >= 1)
        assertNull(UdpAssociationTable.getSession(sessionStale.key))
        assertNotNull(UdpAssociationTable.getSession(sessionActive.key))
    }

    @Test
    fun testUdpCorrelationKeyExtractionQuicLongHeader() {
        // Outbound client Initial packet:
        // Byte 0: 0xC0 (Long Header, Initial)
        // Bytes 1..4: Version (0x00000001)
        // Byte 5: DCIL (4 bytes)
        // Bytes 6..9: DCID (0x11, 0x22, 0x33, 0x44)
        // Byte 10: SCIL (4 bytes)
        // Bytes 11..14: SCID (0xAA, 0xBB, 0xCC, 0xDD)
        val clientPacket = ByteArray(30)
        clientPacket[0] = 0xC0.toByte()
        clientPacket[1] = 0x00; clientPacket[2] = 0x00; clientPacket[3] = 0x00; clientPacket[4] = 0x01
        clientPacket[5] = 4 // DCIL
        clientPacket[6] = 0x11.toByte(); clientPacket[7] = 0x22.toByte(); clientPacket[8] = 0x33.toByte(); clientPacket[9] = 0x44.toByte()
        clientPacket[10] = 4 // SCIL
        clientPacket[11] = 0xAA.toByte(); clientPacket[12] = 0xBB.toByte(); clientPacket[13] = 0xCC.toByte(); clientPacket[14] = 0xDD.toByte()

        val clientKey = UdpTransportHandler.extractCorrelationKey(clientPacket, 0, clientPacket.size, 443, isOutbound = true)
        assertEquals("quic:aabbccdd", clientKey)

        // Inbound server Initial/Handshake packet:
        // Server addresses client, so server DCID == client SCID
        val serverPacket = ByteArray(30)
        serverPacket[0] = 0xC0.toByte()
        serverPacket[1] = 0x00; serverPacket[2] = 0x00; serverPacket[3] = 0x00; serverPacket[4] = 0x01
        serverPacket[5] = 4 // DCIL
        serverPacket[6] = 0xAA.toByte(); serverPacket[7] = 0xBB.toByte(); serverPacket[8] = 0xCC.toByte(); serverPacket[9] = 0xDD.toByte() // Server DCID == client SCID

        val serverKey = UdpTransportHandler.extractCorrelationKey(serverPacket, 0, serverPacket.size, 443, isOutbound = false)
        assertEquals("quic:aabbccdd", serverKey)
        assertEquals(clientKey, serverKey)
    }

    @Test
    fun testUdpQuicShortHeaderProbeMatching() {
        val clientIp = InetAddress.getByName("127.0.0.1")
        val session = UdpAssociationTable.getOrCreateSession(
            sessionId = "quic-session",
            clientAddress = clientIp,
            clientPort = 49152,
            destinationHost = "example.com",
            destinationPort = 443,
            strategy = BypassStrategy.UDP_QUIC_PAD
        )

        val probe = UdpPendingProbe(
            host = "example.com",
            strategy = BypassStrategy.UDP_QUIC_PAD,
            sentTime = System.currentTimeMillis() - 50,
            correlationKey = "quic:11223344"
        )
        session.addProbe(probe)

        // Server sends 1-RTT Short Header packet:
        // Byte 0: 0x43 (Header Form = 0, Fixed Bit = 1)
        // Bytes 1..4: DCID (0x11, 0x22, 0x33, 0x44)
        val shortHeaderPacket = ByteArray(20)
        shortHeaderPacket[0] = 0x43.toByte()
        shortHeaderPacket[1] = 0x11.toByte()
        shortHeaderPacket[2] = 0x22.toByte()
        shortHeaderPacket[3] = 0x33.toByte()
        shortHeaderPacket[4] = 0x44.toByte()

        val matched = session.popMatchingQuicShortHeader(shortHeaderPacket, 0, shortHeaderPacket.size)
        assertNotNull(matched)
        assertEquals(BypassStrategy.UDP_QUIC_PAD, matched?.strategy)
        assertEquals("quic:11223344", matched?.correlationKey)
    }

    @Test
    fun testBootstrapDnsLookupAndRecursionSafety() {
        val bootstrapDns = BootstrapDns()
        
        // 1. IP literal resolution (no network query)
        val ipRes = bootstrapDns.lookup("1.1.1.1")
        assertEquals(1, ipRes.size)
        assertEquals("1.1.1.1", ipRes[0].hostAddress)

        // 2. Known DoH providers
        val googleDns = bootstrapDns.lookup("dns.google")
        assertTrue(googleDns.isNotEmpty())
        assertTrue(googleDns.any { it.hostAddress == "8.8.8.8" || it.hostAddress == "8.8.4.4" })

        // 3. Unknown host fallback does not throw or loop infinitely
        val fallback = bootstrapDns.lookup("nonexistent.invalid.domain")
        assertNotNull(fallback)
    }
}
