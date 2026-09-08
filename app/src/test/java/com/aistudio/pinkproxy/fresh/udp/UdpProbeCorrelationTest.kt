package com.aistudio.pinkproxy.fresh.udp

import com.aistudio.pinkproxy.fresh.*
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import java.net.InetAddress

class UdpProbeCorrelationTest {

    @Before
    fun setup() {
        StrategyStateRepository.clearProfileState("DEFAULT")
    }

    @Test
    fun `test matching probe with correlation key succeeds`() {
        val key = UdpSessionKey(InetAddress.getByName("127.0.0.1"), 12345, "test.com", 443)
        val association = UdpAssociation(key, strategy = BypassStrategy.UDP_COMBINED_HYBRID)
        
        val correlationKey = "quic:abcd1234abcd1234"
        val probe = UdpPendingProbe("test.com", BypassStrategy.UDP_COMBINED_HYBRID, correlationKey = correlationKey)
        
        association.addProbe(probe)
        
        // Exact match
        val matched = association.popMatchingProbe(correlationKey)
        assertNotNull(matched)
        assertEquals(probe.probeId, matched?.probeId)
    }

    @Test
    fun `test mismatching correlation key drops probe without attribution`() {
        val key = UdpSessionKey(InetAddress.getByName("127.0.0.1"), 12345, "test.com", 443)
        val association = UdpAssociation(key, strategy = BypassStrategy.UDP_COMBINED_HYBRID)
        
        val probe = UdpPendingProbe("test.com", BypassStrategy.UDP_COMBINED_HYBRID, correlationKey = "quic:real")
        association.addProbe(probe)
        
        // Mismatch request
        val matched = association.popMatchingProbe("quic:fake")
        assertNull("Should not return probe on mismatch", matched)
        
        // Popping the probe normally shouldn't match either because it has a correlation key, but if we pass null it won't pop it
        val matchedNull = association.popMatchingProbe(null)
        assertNull("Should not pop probe with strict correlation if passing null", matchedNull)
    }
}
