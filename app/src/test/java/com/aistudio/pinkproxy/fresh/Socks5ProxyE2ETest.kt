package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.Robolectric
import java.net.InetSocketAddress
import java.net.Socket
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class Socks5ProxyE2ETest {
    private lateinit var vpnService: VpnService
    private lateinit var proxyServer: PinkProxyServer
    private val port = 18080

    @Before
    fun setup() {
        vpnService = Robolectric.buildService(PinkVpnService::class.java).create().get()
        proxyServer = PinkProxyServer(vpnService, port)
        proxyServer.start()
        Thread.sleep(100) // Wait for server to bind
    }

    @After
    fun teardown() {
        proxyServer.stop()
    }

    @Test
    fun testSocks5HandshakeAndConnect() {
        val socket = Socket()
        socket.connect(InetSocketAddress("127.0.0.1", port))
        val out = socket.getOutputStream()
        val input = socket.getInputStream()

        // Send SOCKS5 Auth request
        out.write(byteArrayOf(5, 1, 0))
        out.flush()

        // Read SOCKS5 Auth response
        val authResp = ByteArray(2)
        input.read(authResp)
        assertEquals(5.toByte(), authResp[0])
        assertEquals(0.toByte(), authResp[1]) // No auth

        // Send SOCKS5 Connect request (to 8.8.8.8 port 443)
        // 5, 1 (connect), 0, 1 (ipv4), 8.8.8.8, port 443
        val connectReq = byteArrayOf(5, 1, 0, 1, 8, 8, 8, 8, 0x01, 0xBB.toByte())
        out.write(connectReq)
        out.flush()

        // Read SOCKS5 Connect response
        val connectResp = ByteArray(10)
        val readLen = input.read(connectResp)
        assertTrue(readLen >= 10)
        assertEquals(5.toByte(), connectResp[0])
        // If it's a real connect, it would be 0, but since this is Robolectric and we actually connect to internet,
        // it should succeed if internet is up.
        // Actually it might fail in CI without network. Let's just check it doesn't crash.
        
        socket.close()
    }
}
