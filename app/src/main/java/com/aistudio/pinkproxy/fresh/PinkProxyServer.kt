package com.aistudio.pinkproxy.fresh

import android.content.Context
import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.net.*
import java.nio.ByteBuffer
import java.util.*
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.io.*
class PinkProxyServer(private val vpnService: VpnService, private val port: Int) {
    private var serverJob: Job? = null
    private var serverSocket: ServerSocket? = null

    companion object {
        private val SOCKS5_AUTH_SUCCESS = byteArrayOf(5, 0)
        private val SOCKS5_CONNECT_SUCCESS = byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0)
    }

    fun start() {
        if (serverJob?.isActive == true) return
        
        val parentJob = SupervisorJob()
        val scope = CoroutineScope(Dispatchers.IO + parentJob)
        serverJob = parentJob
        
        ProxyStats.startSpeedMonitor(scope)
        
        
        scope.launch {
            try {
                serverSocket = ServerSocket().apply {
                    reuseAddress = true
                    bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port))
                }
                ProxyStats.logRecovery("Proxy server started on port $port")
                while (isActive) {
                    val client = try {
                        serverSocket?.accept()
                    } catch (e: SocketException) {
                        null
                    } ?: break
                    
                    launch { handleClient(client) }
                }
            } catch (e: Exception) {
                if (isActive) Log.e("PinkProxy", "Server error", e)
            } finally {
                try { serverSocket?.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                serverSocket = null
            }
        }
    }

    fun stop() {
        serverJob?.cancel()
        try { serverSocket?.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        serverSocket = null
    }

    private suspend fun readExactly(input: InputStream, buffer: ByteArray, offset: Int, length: Int) {
        var read = 0
        while (read < length) {
            val r = input.read(buffer, offset + read, length - read)
            if (r == -1) throw IOException("EOF")
            read += r
        }
    }

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class, kotlinx.coroutines.DelicateCoroutinesApi::class)
    private suspend fun handleClient(client: Socket) {
        ProxyStats.updateConnections(1)
        try {
            client.soTimeout = 10000
            val input = client.getInputStream()
            val output = client.getOutputStream()

            // 1. Version identifier/method selection message
            val version = input.read()
            if (version == -1) return
            if (version != 5) {
                client.close()
                return
            }

            val nMethods = input.read()
            if (nMethods == -1) return
            val methods = ByteArray(nMethods)
            readExactly(input, methods, 0, nMethods)

            // No authentication required
            output.write(SOCKS5_AUTH_SUCCESS)
            output.flush()

            // 2. Request details
            val version2 = input.read()
            if (version2 != 5) return
            val cmd = input.read()
            input.read() // RSV
            val atyp = input.read()

            if (cmd == 3) { // UDP ASSOCIATE
                UdpTransportHandler.handleUdpAssociate(client, output, vpnService, PinkVpnService.instance?.getServiceScope() ?: GlobalScope)
                return
            }
            if (cmd != 1) { // CONNECT ONLY
                client.close()
                return
            }

            val host = when (atyp) {
                1 -> { // IPv4
                    val addr = ByteArray(4)
                    readExactly(input, addr, 0, 4)
                    InetAddress.getByAddress(addr).hostAddress
                }
                3 -> { // Domain name
                    val len = input.read()
                    if (len == -1) throw IOException("EOF")
                    val addr = ByteArray(len)
                    readExactly(input, addr, 0, len)
                    String(addr)
                }
                4 -> { // IPv6
                    val addr = ByteArray(16)
                    readExactly(input, addr, 0, 16)
                    InetAddress.getByAddress(addr).hostAddress
                }
                else -> {
                    client.close()
                    return
                }
            }
            val portBytes = ByteArray(2)
            readExactly(input, portBytes, 0, 2)
            val targetPort = ((portBytes[0].toInt() and 0xff) shl 8) or (portBytes[1].toInt() and 0xff)
            
            // SOCKS5 success response
            if (ProxyStats.censorshipIntensity.value > 85) delay(java.util.concurrent.ThreadLocalRandom.current().nextLong(10, 50))
            output.write(SOCKS5_CONNECT_SUCCESS)
            output.flush()
            
            client.soTimeout = 0 // Remove timeout for the tunneled connection
            try { client.keepAlive = true } catch (e: Exception) {}
            TcpTransportHandler.handleTcpSession(client, host ?: "", targetPort, vpnService, PinkVpnService.instance?.getServiceScope() ?: GlobalScope)

        } catch (e: Exception) {
            Log.v("PinkProxy", "Client handling error: ${e.message}")
        } finally {
            try { client.close() } catch (ex: Exception) {}
            ProxyStats.updateConnections(-1)
        }
    }
}
