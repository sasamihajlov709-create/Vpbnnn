package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import io.mockk.*
import java.net.InetAddress
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.Robolectric
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class Socks5ProxyE2ETest {

    private lateinit var vpnService: VpnService
    private lateinit var proxyServer: PinkProxyServer
    private var proxyPort = 0
    private var mockTargetServer: ServerSocket? = null
    private var mockTargetPort = 0

    @Before
    fun setup() {
        vpnService = Robolectric.buildService(PinkVpnService::class.java).create().get()
        ProxyDispatcher.context = Robolectric.setupService(PinkVpnService::class.java)
        
        mockkObject(ProxyStats)
        mockkObject(VpnRuntimeState)
        
        // Start a local mock echo target server
        mockTargetServer = ServerSocket(0)
        mockTargetPort = mockTargetServer!!.localPort
        thread(name = "MockTargetServer") {
            try {
                while (mockTargetServer?.isClosed == false) {
                    val client = mockTargetServer?.accept() ?: break
                    thread(name = "MockTargetClient") {
                        client.use { s ->
                            s.soTimeout = 5000
                            val input = s.getInputStream()
                            val output = s.getOutputStream()
                            val buf = ByteArray(1024)
                            try {
                                val len = input.read(buf)
                                if (len > 0) {
                                    output.write(buf, 0, len)
                                    output.flush()
                                }
                            } catch (e: Exception) {}
                        }
                    }
                }
            } catch (ignored: Exception) {}
        }

        // Find free port for proxy server
        val tempSock = ServerSocket(0)
        proxyPort = tempSock.localPort
        tempSock.close()

        proxyServer = PinkProxyServer(vpnService, proxyPort)
        proxyServer.start()
        Thread.sleep(800) // Increased wait for server to bind
    }

    @After
    fun teardown() {
        proxyServer.stop()
        mockTargetServer?.close()
        unmockkAll()
    }

    @Test
    fun testSocks5HandshakeAndConnectSuccess() {
        Socket("127.0.0.1", proxyPort).use { client ->
            client.soTimeout = 10000
            val dos = DataOutputStream(client.getOutputStream())
            val dis = DataInputStream(client.getInputStream())

            // 1. Send SOCKS5 Greeting (No Auth)
            dos.write(byteArrayOf(0x05, 0x01, 0x00))
            dos.flush()

            val ver = dis.readByte()
            val method = dis.readByte()
            assertEquals(0x05.toByte(), ver)
            assertEquals(0x00.toByte(), method)

            // 2. Send SOCKS5 Connect Request to local mock target
            val request = mutableListOf<Byte>()
            request.add(0x05) // Version
            request.add(0x01) // CONNECT
            request.add(0x00) // Reserved
            request.add(0x01) // IPv4
            request.addAll(listOf(127, 0, 0, 1).map { it.toByte() })
            request.add((mockTargetPort shr 8).toByte())
            request.add((mockTargetPort and 0xFF).toByte())

            dos.write(request.toByteArray())
            dos.flush()

            // 3. Read SOCKS5 Response
            val respVer = dis.readByte()
            val respReply = dis.readByte()
            val respRsv = dis.readByte()
            val respAtyp = dis.readByte()
            
            val addrLen = if (respAtyp == 0x01.toByte()) 4 else 16
            val dummyAddr = ByteArray(addrLen)
            dis.readFully(dummyAddr)
            val dummyPort = dis.readUnsignedShort()

            assertEquals(0x05.toByte(), respVer)
            assertEquals(0x00.toByte(), respReply) // 0x00 = Succeeded!

            // 4. Send echo payload through proxy
            val ping = "HelloPinkProxy".toByteArray()
            dos.write(ping)
            dos.flush()

            val reply = ByteArray(ping.size)
            dis.readFully(reply)
            assertEquals("HelloPinkProxy", String(reply))
        }
    }

    private fun readAsciiLine(input: java.io.InputStream): String {
        val sb = StringBuilder()
        while (true) {
            val b = input.read()
            if (b == -1 || b == '\n'.code) break
            if (b != '\r'.code) sb.append(b.toChar())
        }
        return sb.toString()
    }

    @Test
    fun testHttpConnectHandshakeSuccess() {
        Socket("127.0.0.1", proxyPort).use { client ->
            client.soTimeout = 10000
            val output = client.getOutputStream()
            val input = client.getInputStream()

            val connectReq = "CONNECT 127.0.0.1:$mockTargetPort HTTP/1.1\r\nHost: 127.0.0.1:$mockTargetPort\r\n\r\n"
            output.write(connectReq.toByteArray())
            output.flush()

            val statusLine = readAsciiLine(input)
            assertTrue("Status line should contain 200 Connection Established: $statusLine", statusLine.contains("200"))

            // Drain headers until empty line without buffering ahead
            var line: String
            do {
                line = readAsciiLine(input)
            } while (line.isNotEmpty())

            // Send payload after CONNECT established
            output.write("HTTPConnectPing".toByteArray())
            output.flush()

            val buf = ByteArray(15)
            val len = input.read(buf)
            assertEquals(15, len)
            assertEquals("HTTPConnectPing", String(buf, 0, len))
        }
    }
}
