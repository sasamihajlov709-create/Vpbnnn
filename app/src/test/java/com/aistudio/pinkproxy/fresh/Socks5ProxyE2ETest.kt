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
        // Start a dummy echo server
        val echoServer = java.net.ServerSocket(0)
        val targetPort = echoServer.localPort
        
        val echoThread = Thread {
            try {
                val client = echoServer.accept()
                val clientIn = client.getInputStream()
                val clientOut = client.getOutputStream()
                val buffer = ByteArray(1024)
                val read = clientIn.read(buffer)
                if (read > 0) {
                    clientOut.write(buffer, 0, read)
                    clientOut.flush()
                }
                client.close()
            } catch (e: Exception) {}
        }
        echoThread.start()
        
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

        // Send SOCKS5 Connect request to our dummy echo server
        val portHigh = (targetPort shr 8).toByte()
        val portLow = (targetPort and 0xFF).toByte()
        val connectReq = byteArrayOf(5, 1, 0, 1, 127, 0, 0, 1, portHigh, portLow)
        out.write(connectReq)
        out.flush()

        // Read SOCKS5 Connect response
        val connectResp = ByteArray(10)
        val readLen = input.read(connectResp)
        assertTrue(readLen >= 10)
        assertEquals(5.toByte(), connectResp[0])
        
        socket.close()
        echoServer.close()
    }
}
