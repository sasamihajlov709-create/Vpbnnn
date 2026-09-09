package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.net.InetAddress
import java.net.InetSocketAddress

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], manifest = Config.NONE)
class UdpCorrelationStrictTest {

    @Before
    fun setup() {
        UdpAssociationTable.clear()
    }

    @Test
    fun `test udp correlation prevents misattribution on out-of-order responses`() = runTest {
        val destHost = "1.1.1.1"
        val destPort = 53
        val clientIp = InetAddress.getByName("10.0.0.2")
        
        val sessionAId = "socks-udp-1"
        val sessionBId = "socks-udp-2"
        
        val sessionA = UdpAssociationTable.getOrCreateSession(
            sessionId = sessionAId,
            clientAddress = clientIp,
            clientPort = 10001,
            destinationHost = destHost,
            destinationPort = destPort,
            strategy = BypassStrategy.TCP_OOB_DESYNC
        )
        
        val sessionB = UdpAssociationTable.getOrCreateSession(
            sessionId = sessionBId,
            clientAddress = clientIp,
            clientPort = 10002,
            destinationHost = destHost,
            destinationPort = destPort,
            strategy = BypassStrategy.SNI_SPLIT
        )
        
        val keyB = UdpSessionKey(clientIp, 10002, destHost, destPort)
        val keyA = UdpSessionKey(clientIp, 10001, destHost, destPort)
        
        val resolvedB = UdpAssociationTable.getSession(keyB)
        assertNotNull("Association B should exist", resolvedB)
        assertEquals(BypassStrategy.SNI_SPLIT, resolvedB?.strategy)
        
        val resolvedA = UdpAssociationTable.getSession(keyA)
        assertNotNull("Association A should exist", resolvedA)
        assertEquals(BypassStrategy.TCP_OOB_DESYNC, resolvedA?.strategy)
        
        UdpAssociationTable.removeSession(keyB)
        assertNull(UdpAssociationTable.getSession(keyB))
        assertNotNull(UdpAssociationTable.getSession(keyA))
    }
}
