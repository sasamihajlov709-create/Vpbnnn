package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.Robolectric
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class Socks5SecurityAuthTest {

    private lateinit var vpnService: VpnService
    private lateinit var proxyServer: PinkProxyServer
    private var proxyPort = 0
    private val testSecret = "TestSecureSecret123"

    @Before
    fun setup() {
        vpnService = Robolectric.buildService(PinkVpnService::class.java).create().get()
        ProxyDispatcher.context = vpnService.applicationContext

        val tempSock = ServerSocket(0)
        proxyPort = tempSock.localPort
        tempSock.close()

        proxyServer = PinkProxyServer(vpnService, proxyPort, testSecret)
        proxyServer.start()
        Thread.sleep(600)
    }

    @After
    fun teardown() {
        if (::proxyServer.isInitialized) {
            proxyServer.stop()
        }
    }

    @Test
    fun testNoAuthConnectionIsStrictlyRejectedWhenSecretConfigured() {
        Socket("127.0.0.1", proxyPort).use { client ->
            client.soTimeout = 3000
            val dos = DataOutputStream(client.getOutputStream())
            val dis = DataInputStream(client.getInputStream())

            // Client attempts NO_AUTH (method 0x00)
            dos.write(byteArrayOf(0x05, 0x01, 0x00))
            dos.flush()

            val ver = dis.readByte()
            val selectedMethod = dis.readByte()

            assertEquals(0x05.toByte(), ver)
            // Must return 0xFF (No acceptable methods)
            assertEquals(0xFF.toByte(), selectedMethod)
        }
    }

    @Test
    fun testUserPassAuthSucceedsWithValidSecret() {
        Socket("127.0.0.1", proxyPort).use { client ->
            client.soTimeout = 3000
            val dos = DataOutputStream(client.getOutputStream())
            val dis = DataInputStream(client.getInputStream())

            // 1. Client advertises USER/PASS (method 0x02)
            dos.write(byteArrayOf(0x05, 0x01, 0x02))
            dos.flush()

            val ver = dis.readByte()
            val selectedMethod = dis.readByte()
            assertEquals(0x05.toByte(), ver)
            assertEquals(0x02.toByte(), selectedMethod)

            // 2. Client sends credentials
            val secBytes = testSecret.toByteArray(StandardCharsets.UTF_8)
            val authReq = ByteArray(3 + secBytes.size * 2)
            authReq[0] = 0x01
            authReq[1] = secBytes.size.toByte()
            System.arraycopy(secBytes, 0, authReq, 2, secBytes.size)
            authReq[2 + secBytes.size] = secBytes.size.toByte()
            System.arraycopy(secBytes, 0, authReq, 3 + secBytes.size, secBytes.size)

            dos.write(authReq)
            dos.flush()

            val authVer = dis.readByte()
            val authStatus = dis.readByte()

            assertEquals(0x01.toByte(), authVer)
            assertEquals(0x00.toByte(), authStatus) // 0x00 = Auth Success
        }
    }

    @Test
    fun testUserPassAuthFailsWithInvalidSecret() {
        Socket("127.0.0.1", proxyPort).use { client ->
            client.soTimeout = 3000
            val dos = DataOutputStream(client.getOutputStream())
            val dis = DataInputStream(client.getInputStream())

            // 1. Greeting
            dos.write(byteArrayOf(0x05, 0x01, 0x02))
            dos.flush()

            dis.readByte()
            dis.readByte()

            // 2. Send bogus password
            val badSecret = "WrongPassword".toByteArray(StandardCharsets.UTF_8)
            val authReq = ByteArray(3 + badSecret.size * 2)
            authReq[0] = 0x01
            authReq[1] = badSecret.size.toByte()
            System.arraycopy(badSecret, 0, authReq, 2, badSecret.size)
            authReq[2 + badSecret.size] = badSecret.size.toByte()
            System.arraycopy(badSecret, 0, authReq, 3 + badSecret.size, badSecret.size)

            dos.write(authReq)
            dos.flush()

            val authVer = dis.readByte()
            val authStatus = dis.readByte()

            assertEquals(0x01.toByte(), authVer)
            assertNotEquals(0x00.toByte(), authStatus) // Must fail
        }
    }
}
