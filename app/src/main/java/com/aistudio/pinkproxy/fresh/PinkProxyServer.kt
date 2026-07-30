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
class PinkProxyServer(private val vpnService: VpnService, private val port: Int, val sessionSecret: String = "") {
    private var serverJob: Job? = null
    private var serverSocket: ServerSocket? = null
    private val activeConnectionSemaphore = Semaphore(2000)

    companion object {
        private val SOCKS5_AUTH_SUCCESS = byteArrayOf(5, 0)
        private val SOCKS5_AUTH_USER_PASS = byteArrayOf(5, 2)
        private val SOCKS5_AUTH_NO_ACCEPTABLE = byteArrayOf(5, 0xFF.toByte())
        private val SOCKS5_CONNECT_SUCCESS = byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0)
    }

    fun start() {
        if (serverJob?.isActive == true) return
        
        val parentJob = SupervisorJob()
        val scope = CoroutineScope(ProxyDispatcher.io + parentJob)
        serverJob = parentJob
        
        ProxyStats.startSpeedMonitor(scope)
        
        // Connection Watchdog to prevent leaks and stuck workers
        scope.launch {
            while (isActive) {
                delay(60000)
                val activeCount = 2000 - activeConnectionSemaphore.availablePermits()
                if (activeCount > 500) {
                    Log.i("PinkProxy", "Watchdog: $activeCount active connections. Cleaning up...")
                    // If semaphore is nearly empty, we might have leaked permits
                    if (activeCount > 1800) {
                        Log.e("PinkProxy", "CRITICAL: Semaphore exhaustion. Force resetting permits.")
                        activeConnectionSemaphore.release(2000 - activeConnectionSemaphore.availablePermits())
                    }
                }
                
                // Force memory cleanup if needed
                if (activeCount > 1000) {
                    System.gc()
                }
            }
        }
        
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

                    if (!activeConnectionSemaphore.tryAcquire()) {
                        try { client.close() } catch (e: Throwable) {}
                        continue
                    }
                    
                    val clientJob = scope.launch {
                        try {
                            client.tcpNoDelay = true
                            try { client.sendBufferSize = 64 * 1024 } catch (e: Throwable) {}
                            try { client.receiveBufferSize = 64 * 1024 } catch (e: Throwable) {}
                            handleClient(client, this)
                        } finally {
                            activeConnectionSemaphore.release()
                        }
                    }
                }
            } catch (e: Throwable) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                if (isActive) Log.e("PinkProxy", "Server error", e)
            } finally {
                try { serverSocket?.close() } catch (e: Throwable) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                serverSocket = null
            }
        }
    }

    fun stop() {
        serverJob?.cancel()
        try { serverSocket?.close() } catch (e: Throwable) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
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

    private suspend fun handleHttpProxy(client: Socket, firstByte: Int, input: InputStream, output: OutputStream, scope: CoroutineScope) {
        val line = StringBuilder()
        line.append(firstByte.toChar())
        var b: Int
        while (true) {
            b = input.read()
            if (b == -1 || b == '\n'.code) break
            line.append(b.toChar())
        }
        
        val firstLine = line.toString().trim()
        val parts = firstLine.split(" ")
        if (parts.size < 2) { client.close(); return }
        
        val method = parts[0].uppercase()
        val target = parts[1]
        
        var host: String
        var port: Int
        
        if (method == "CONNECT") {
            val hostPort = target.split(":")
            host = hostPort[0]
            port = if (hostPort.size > 1) hostPort[1].toIntOrNull() ?: 443 else 443
            
            // Consume remaining headers
            while (true) {
                line.clear()
                while (true) {
                    b = input.read()
                    if (b == -1 || b == '\n'.code) break
                    line.append(b.toChar())
                }
                if (line.toString().trim().isEmpty()) break
            }
            
            output.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
            output.flush()
        } else {
            // Simplified: only CONNECT for tunneling. For GET/POST we'd need full proxy logic.
            client.close()
            return
        }
        
        client.soTimeout = 0
        TcpTransportHandler.handleTcpSession(client, host, port, vpnService, scope)
    }

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class, kotlinx.coroutines.DelicateCoroutinesApi::class)
    private suspend fun handleClient(client: Socket, scope: CoroutineScope) {
        // UID Verification for Android 10+ (API 29+)
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
            try {
                val cm = vpnService.getSystemService(Context.CONNECTIVITY_SERVICE) as? android.net.ConnectivityManager
                val remoteEndpoint = client.remoteSocketAddress as? InetSocketAddress
                val localEndpoint = client.localSocketAddress as? InetSocketAddress
                if (cm != null && remoteEndpoint != null && localEndpoint != null) {
                    val uid = cm.getConnectionOwnerUid(android.system.OsConstants.IPPROTO_TCP, remoteEndpoint, localEndpoint)
                    if (uid != -1 && uid != android.os.Process.myUid()) {
                        Log.w("PinkProxy", "Rejected unauthorized proxy access attempt from UID $uid")
                        client.close()
                        return
                    }
                }
            } catch (e: Throwable) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                Log.v("PinkProxy", "UID check exception: ${e.message}")
            }
        }

        ProxyStats.updateConnections(1)
        try {
            client.soTimeout = 10000
            val input = client.getInputStream()
            val output = client.getOutputStream()

            // 1. Version identifier/method selection message
            val version = input.read()
            if (version == -1) return
            
            if (version == 'C'.code || version == 'G'.code || version == 'P'.code) {
                handleHttpProxy(client, version, input, output, scope)
                return
            }

            if (version != 5) {
                client.close()
                return
            }

            val nMethods = input.read()
            if (nMethods == -1) return
            val methods = ByteArray(nMethods)
            readExactly(input, methods, 0, nMethods)

            val supportsNoAuth = methods.contains(0.toByte())
            val supportsUserPass = methods.contains(2.toByte())

            if (supportsUserPass && sessionSecret.isNotEmpty()) {
                output.write(SOCKS5_AUTH_USER_PASS)
                output.flush()

                val subVer = input.read()
                if (subVer != 1) { client.close(); return }
                val uLen = input.read()
                if (uLen <= 0) { client.close(); return }
                val usernameBytes = ByteArray(uLen)
                readExactly(input, usernameBytes, 0, uLen)
                val pLen = input.read()
                if (pLen <= 0) { client.close(); return }
                val passwordBytes = ByteArray(pLen)
                readExactly(input, passwordBytes, 0, pLen)

                val uname = String(usernameBytes, java.nio.charset.StandardCharsets.UTF_8)
                val passwd = String(passwordBytes, java.nio.charset.StandardCharsets.UTF_8)

                if (uname == sessionSecret && passwd == sessionSecret) {
                    output.write(byteArrayOf(1, 0)) // Auth success
                    output.flush()
                } else {
                    output.write(byteArrayOf(1, 1)) // Auth failed
                    output.flush()
                    client.close()
                    return
                }
            } else if (supportsNoAuth) {
                output.write(SOCKS5_AUTH_SUCCESS)
                output.flush()
            } else {
                output.write(SOCKS5_AUTH_NO_ACCEPTABLE)
                output.flush()
                client.close()
                return
            }

            // 2. Request details
            val version2 = input.read()
            if (version2 != 5) return
            val cmd = input.read()
            input.read() // RSV
            val atyp = input.read()

            if (cmd == 3) { // UDP ASSOCIATE
                UdpTransportHandler.handleUdpAssociate(client, output, vpnService, scope)
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
                    String(addr, java.nio.charset.StandardCharsets.UTF_8)
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
            try { client.keepAlive = true } catch (e: Throwable) {}
            TcpTransportHandler.handleTcpSession(client, host ?: "", targetPort, vpnService, scope)

        } catch (e: Throwable) {
            if (e is kotlinx.coroutines.CancellationException) throw e
            Log.v("PinkProxy", "Client handling error: ${e.message}")
        } finally {
            try { client.close() } catch (ex: Throwable) {}
            ProxyStats.updateConnections(-1)
        }
    }
}
