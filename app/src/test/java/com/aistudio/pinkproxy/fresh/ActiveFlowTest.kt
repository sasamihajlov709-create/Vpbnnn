package com.aistudio.pinkproxy.fresh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class ActiveFlowTest {

    @Test
    fun testActiveFlowFromContext() {
        val context = FlowContext(
            host = "example.com",
            port = 443,
            transport = TransportType.TCP,
            strategy = BypassStrategy.SNI_SPLIT
        )

        val flow = ActiveFlow.fromContext(context, reasoning = "Learned optimal strategy")
        assertEquals(context.sessionId, flow.id)
        assertEquals("example.com", flow.host)
        assertEquals(TransportType.TCP, flow.transport)
        assertEquals("TCP", flow.type)
        assertEquals(BypassStrategy.SNI_SPLIT, flow.strategy)
        assertEquals("Learned optimal strategy", flow.reasoning)
        assertEquals("ACTIVE", flow.status)
    }

    @Test
    fun testProxyStatsFlowContextRegistration() {
        val context = FlowContext(
            host = "dns.google",
            port = 53,
            transport = TransportType.DNS,
            strategy = BypassStrategy.DNS_OVER_TCP
        )

        val flow = ActiveFlow.fromContext(context, reasoning = "DNS tunneling")
        ProxyStats.registerFlow(context, reasoning = "DNS tunneling")
        val currentFlow = ProxyStats.getFlow(context.sessionId)
        assertNotNull(currentFlow)
        assertEquals("dns.google", currentFlow?.host)
        assertEquals(TransportType.DNS, currentFlow?.transport)
        assertEquals("DNS", currentFlow?.type)
        assertEquals(BypassStrategy.DNS_OVER_TCP, currentFlow?.strategy)

        ProxyStats.closeFlow(context.sessionId)
        ProxyStats.removeFlow(context.sessionId)
    }
}
