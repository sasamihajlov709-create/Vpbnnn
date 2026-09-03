package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Test

class StrategySemanticAuditTest {

    @Test
    fun testAllStrategiesHaveValidManipulationLevel() {
        val totalStrategies = BypassStrategy.entries.size
        assertTrue("Total strategies count should be > 200", totalStrategies >= 225)

        for (strategy in BypassStrategy.entries) {
            assertNotNull("Strategy $strategy must have a non-null manipulationLevel", strategy.manipulationLevel)

            // Test boolean helper properties
            val flags = listOf(strategy.isPacketLevel, strategy.isProtocolLevel, strategy.isStreamLevel)
            assertEquals(
                "Strategy $strategy must satisfy exactly one manipulationLevel helper boolean",
                1,
                flags.count { it }
            )

            when (strategy.manipulationLevel) {
                ManipulationLevel.PACKET_LEVEL -> assertTrue(strategy.isPacketLevel)
                ManipulationLevel.PROTOCOL_LEVEL -> assertTrue(strategy.isProtocolLevel)
                ManipulationLevel.STREAM_LEVEL -> assertTrue(strategy.isStreamLevel)
            }
        }
    }

    @Test
    fun testSemanticDistribution() {
        val streamLevelCount = BypassStrategy.entries.count { it.isStreamLevel }
        val protocolLevelCount = BypassStrategy.entries.count { it.isProtocolLevel }
        val packetLevelCount = BypassStrategy.entries.count { it.isPacketLevel }

        assertTrue("Stream level strategies should be substantial ($streamLevelCount)", streamLevelCount > 40)
        assertTrue("Protocol level strategies should be substantial ($protocolLevelCount)", protocolLevelCount > 80)
        assertTrue("Packet level strategies should be accurately identified ($packetLevelCount)", packetLevelCount > 30)

        assertEquals(
            "Sum of all manipulation levels must equal total strategy count",
            BypassStrategy.entries.size,
            streamLevelCount + protocolLevelCount + packetLevelCount
        )
    }

    @Test
    fun testProtocolLevelStrategiesFamilyConsistency() {
        // Verify that application-layer manglers (HTTP, TLS) are generally PROTOCOL_LEVEL or STREAM_LEVEL
        for (strategy in BypassStrategy.entries) {
            if (strategy.family == StrategyFamily.HTTP || strategy.family == StrategyFamily.TLS) {
                assertTrue(
                    "HTTP/TLS strategy $strategy should be PROTOCOL_LEVEL or STREAM_LEVEL, found ${strategy.manipulationLevel}",
                    strategy.isProtocolLevel || strategy.isStreamLevel
                )
            }
        }
    }

    @Test
    fun testPacketLevelStrategiesRequirePacketSemantics() {
        for (strategy in BypassStrategy.entries) {
            if (strategy.isPacketLevel) {
                // Packet level strategies deal with TCP flags/windows/timestamps/OOB/SACK/IP headers/fragments
                val name = strategy.name
                val isPacketSemantics = name.contains("PACKET") ||
                    name.contains("IP_") ||
                    name.contains("IPv6") ||
                    name.contains("WINDOW") ||
                    name.contains("SACK") ||
                    name.contains("ACK") ||
                    name.contains("OOB") ||
                    name.contains("RST") ||
                    name.contains("SYN") ||
                    name.contains("FIN") ||
                    name.contains("URGENT") ||
                    name.contains("HANDSHAKE") ||
                    name.contains("SKEW") ||
                    name.contains("TIMESTAMP") ||
                    name.contains("TOS") ||
                    name.contains("REORDER") ||
                    name.contains("RETRANS") ||
                    name.contains("OVERLAP") ||
                    name.contains("DESYNC") ||
                    name.contains("SEGMENT") ||
                    name.contains("GHOST")
                assertTrue(
                    "Packet-level strategy $strategy should have packet-level domain semantics",
                    isPacketSemantics
                )
            }
        }
    }

    @Test
    fun testDirectStrategyIsStreamLevel() {
        assertEquals(ManipulationLevel.STREAM_LEVEL, BypassStrategy.DIRECT.manipulationLevel)
        assertTrue(BypassStrategy.DIRECT.isStreamLevel)
    }
}
