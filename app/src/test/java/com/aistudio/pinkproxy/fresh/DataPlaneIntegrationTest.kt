package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.*
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], manifest = Config.NONE)
class DataPlaneIntegrationTest {

    private lateinit var mockTargetServer: ServerSocket
    private var proxyServer: PinkProxyServer? = null
    private val serverRunning = AtomicBoolean(true)
    private var targetPort = 0
    private var proxyPort = 0

    @Before
    fun setup() {
        // 1. Start mock target server
        mockTargetServer = ServerSocket(0)
        targetPort = mockTargetServer.localPort

        Thread {
            while (serverRunning.get()) {
                try {
                    val client = mockTargetServer.accept()
                    Thread {
                        try {
                            val input = client.getInputStream()
                            val output = client.getOutputStream()
                            val buffer = ByteArray(1024)
                            val read = input.read(buffer)
                            if (read > 0) {
                                val msg = String(buffer, 0, read, StandardCharsets.UTF_8)
                                if (msg == "PING") {
                                    output.write("PONG".toByteArray(StandardCharsets.UTF_8))
                                    output.flush()
                                }
                            }
                        } catch (e: Exception) {
                            // ignore
                        } finally {
                            client.close()
                        }
                    }.start()
                } catch (e: Exception) {
                    if (serverRunning.get()) e.printStackTrace()
                }
            }
        }.start()

        // 2. Start proxy server
        val randomProxySocket = ServerSocket(0)
        proxyPort = randomProxySocket.localPort
        randomProxySocket.close() // Reserve the port

        val mockVpnService = org.robolectric.Robolectric.buildService(PinkVpnService::class.java).get()
        proxyServer = PinkProxyServer(mockVpnService, proxyPort, "testSecret123")
        proxyServer?.start()
    }

    @After
    fun teardown() {
        serverRunning.set(false)
        try { mockTargetServer.close() } catch (e: Exception) {}
        proxyServer?.stop()
        ProxyDispatcher.cancelAllBackgroundJobs()
    }

    @Test
    fun `test end-to-end tcp traffic through proxy server`() = runTest {
        // Wait for proxy to boot
        delay(1000)

        // Simulate SOCKS5 client connection
        var success = false
        var responseMsg = ""

        withContext(Dispatchers.IO) {
            val socket = Socket("127.0.0.1", proxyPort)
            socket.soTimeout = 5000
            val input = socket.getInputStream()
            val output = socket.getOutputStream()

            try {
                // SOCKS5 Handshake
                output.write(byteArrayOf(0x05, 0x01, 0x02)) // Auth method 2 (Username/Password)
                output.flush()

                val authResp = ByteArray(2)
                input.read(authResp)
                assertEquals("Should select username/pwd auth", 0x02.toByte(), authResp[1])

                // SOCKS5 Auth
                val username = "testSecret123".toByteArray()
                val password = "testSecret123".toByteArray()
                val authPacket = ByteArray(3 + username.size + password.size)
                authPacket[0] = 0x01 // Version
                authPacket[1] = username.size.toByte()
                System.arraycopy(username, 0, authPacket, 2, username.size)
                authPacket[2 + username.size] = password.size.toByte()
                System.arraycopy(password, 0, authPacket, 3 + username.size, password.size)
                
                output.write(authPacket)
                output.flush()

                val authStatus = ByteArray(2)
                input.read(authStatus)
                assertEquals("Auth should succeed", 0x00.toByte(), authStatus[1])

                // SOCKS5 Connect Command to local target
                val connectCmd = ByteArray(10)
                connectCmd[0] = 0x05 // Version
                connectCmd[1] = 0x01 // Connect
                connectCmd[2] = 0x00 // Rsvd
                connectCmd[3] = 0x01 // IPv4
                // 127.0.0.1
                connectCmd[4] = 127.toByte()
                connectCmd[5] = 0
                connectCmd[6] = 0
                connectCmd[7] = 1
                // Port
                connectCmd[8] = (targetPort shr 8).toByte()
                connectCmd[9] = (targetPort and 0xFF).toByte()

                output.write(connectCmd)
                output.flush()

                val connectResp = ByteArray(10)
                input.read(connectResp)
                assertEquals("Connect should succeed", 0x00.toByte(), connectResp[1])

                // Now send data payload
                output.write("PING".toByteArray(StandardCharsets.UTF_8))
                output.flush()

                val payloadResp = ByteArray(4)
                val read = input.read(payloadResp)
                if (read > 0) {
                    responseMsg = String(payloadResp, 0, read, StandardCharsets.UTF_8)
                    if (responseMsg == "PONG") {
                        success = true
                    }
                }
            } finally {
                socket.close()
            }
        }

        assertTrue("End-to-end traffic should flow through the SOCKS5 proxy server", success)
        assertEquals("Response from target should be PONG", "PONG", responseMsg)
    }
}
