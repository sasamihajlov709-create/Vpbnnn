package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Test

class FlowContextTest {

    @Test
    fun testFlowContextCreationAndAttributes() {
        val host = "video.google.com"
        val port = 443
        val strategy = BypassStrategy.SNI_SPLIT
        
        val context = FlowContext(
            host = host,
            port = port,
            transport = TransportType.TCP,
            strategy = strategy
        )

        assertEquals("video.google.com", context.host)
        assertEquals(443, context.port)
        assertEquals(TransportType.TCP, context.transport)
        assertEquals(BypassStrategy.SNI_SPLIT, context.strategy)
        assertTrue("Port 443 must be detected as TLS", context.isTlsPort)
        assertFalse("Port 443 is not DNS", context.isDnsPort)
        assertNotNull("Session ID must be auto-generated", context.sessionId)
        assertTrue(context.creationTime > 0)
    }

    @Test
    fun testFlowContextImmutableMutation() {
        val original = FlowContext(
            host = "discord.gg",
            port = 50001,
            transport = TransportType.UDP,
            strategy = BypassStrategy.DIRECT
        )

        val updatedStrategy = original.withStrategy(BypassStrategy.UDP_COMBINED_HYBRID)
        assertEquals(BypassStrategy.UDP_COMBINED_HYBRID, updatedStrategy.strategy)
        assertEquals(original.sessionId, updatedStrategy.sessionId)
        assertEquals(original.host, updatedStrategy.host)

        val updatedRtt = original.withRtt(120L)
        assertEquals(120L, updatedRtt.rttMs)
    }
}
