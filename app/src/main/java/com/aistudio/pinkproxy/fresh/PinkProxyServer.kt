package com.aistudio.pinkproxy.fresh

import android.content.Context
import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.CancellationException
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
    private val activeConnectionSemaphore = Semaphore(800)

    companion object {
        private val SOCKS5_AUTH_SUCCESS = byteArrayOf(5, 0)
        private val SOCKS5_AUTH_USER_PASS = byteArrayOf(5, 2)
        private val SOCKS5_AUTH_NO_ACCEPTABLE = byteArrayOf(5, 0xFF.toByte())
        private val SOCKS5_CONNECT_SUCCESS = byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0)
    }

    fun start() {
        if (serverJob?.isActive == true) return
        
        val parentJob = SupervisorJob()
        val scope = CoroutineScope(ProxyDispatcher.io + parentJob + ProxyDispatcher.globalHandler)
        serverJob = parentJob
        
        ProxyStats.startSpeedMonitor(scope)
        
        // Connection Watchdog to monitor connections
        scope.launch {
            while (isActive) {
                val watchdogDelay = if (BypassConfig.isPowerSaveMode) 120000L else 60000L
                delay(watchdogDelay)
                val activeCount = 800 - activeConnectionSemaphore.availablePermits()
                if (activeCount > 600) {
                    Log.i("PinkProxy", "Watchdog: $activeCount active connections.")
                }
                
                // Trim buffer pools on low connection load or low battery to free RAM smoothly
                if (activeCount < 50 || BypassConfig.batteryLevel < 15) {
                    ProxyStats.releaseAllPools()
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
                var errorCount = 0
                while (isActive) {
                    val client = try {
                        val c = serverSocket?.accept()
                        errorCount = 0 // Reset error count on successful accept
                        c
                    } catch (e: Exception) {
                        if (!isActive) break
                        Log.e("PinkProxy", "Accept failed, attempt ${errorCount + 1}", e)
                        errorCount++
                        // Exponential backoff to prevent CPU spin during persistent system errors (e.g. EMFILE)
                        delay(minOf(50L * (1 shl minOf(errorCount, 6)), 5000L))
                        continue
                    } ?: break

                    if (!activeConnectionSemaphore.tryAcquire()) {
                        try { client.close() } catch (e: Throwable) {}
                        continue
                    }
                                
                    ProxyStats.updateConnections(1)
                    val clientJob = scope.launch {
                        try {
                            TtlHelper.tuneSocket(client)
                            handleClient(client, this)
                        } catch (e: Throwable) {
                            if (e !is CancellationException) {
                                Log.e("PinkProxy", "Error handling client: ${e.message}")
                            }
                        } finally {
                            try { client.close() } catch (e: Throwable) {}
                            ProxyStats.updateConnections(-1)
                            activeConnectionSemaphore.release()
                        }
                    }
                }
            } catch (e: Throwable) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                if (isActive) {
                    Log.e("PinkProxy", "Server error", e)
                    VpnRuntimeState.updateState(VpnLifecycleState.ERROR, "Internal proxy server error: ${e.localizedMessage}")
                }
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
        var host = "unknown"
        var port = 0
        try {
            val line = java.lang.StringBuilder()
            line.append(firstByte.toChar())
            var b: Int
            
            // Use a short timeout for the initial request line to prevent hanging workers
            client.soTimeout = 5000
            
            while (line.length < 4096) {
                b = input.read()
                if (b == -1 || b == '\n'.code) break
                if (b != '\r'.code) line.append(b.toChar())
            }
            
            val firstLine = line.toString().trim()
            val parts = firstLine.split(" ")
            if (parts.size < 2) { client.close(); return }
            
            val method = parts[0].uppercase()
            val target = parts[1]
            
            if (method == "CONNECT") {
                val hostPort = target.split(":")
                host = hostPort[0]
                port = if (hostPort.size > 1) hostPort[1].toIntOrNull() ?: 443 else 443
                
                // Consume remaining headers with a hard limit to prevent OOM
                var totalRead = 0
                while (totalRead < 64 * 1024) {
                    line.clear()
                    while (line.length < 4096) {
                        b = input.read()
                        totalRead++
                        if (b == -1 || b == '\n'.code) break
                        if (b != '\r'.code) line.append(b.toChar())
                    }
                    if (line.toString().trim().isEmpty()) break
                }
            } else {
                client.close()
                return
            }
            
            client.soTimeout = 0
            TcpTransportHandler.handleTcpSession(
                clientSocket = client,
                targetHost = host,
                targetPort = port,
                vpnService = vpnService,
                scope = scope,
                onConnectSuccess = {
                    output.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
                    output.flush()
                },
                onConnectFailure = { reason ->
                    try {
                        output.write("HTTP/1.1 502 Bad Gateway\r\n\r\n".toByteArray())
                        output.flush()
                    } catch (e: Throwable) {
                        Log.v("PinkProxy", "Failed to close client in HTTP Proxy: ${e.message}")
                    }
                }
            )
        } catch (e: Throwable) {
            Log.e("PinkProxy", "HTTP Proxy error for $host:$port", e)
            try { client.close() } catch (ex: Throwable) {}
        }
    }

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class, kotlinx.coroutines.DelicateCoroutinesApi::class)
    private suspend fun handleClient(client: Socket, scope: CoroutineScope) {
        val startTimestamp = System.currentTimeMillis()
        // UID Verification for Android 10+ (API 29+)
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
            try {
                val cm = vpnService.getSystemService(Context.CONNECTIVITY_SERVICE) as? android.net.ConnectivityManager
                val remoteEndpoint = client.remoteSocketAddress as? InetSocketAddress
                val localEndpoint = client.localSocketAddress as? InetSocketAddress
                if (cm != null && remoteEndpoint != null && localEndpoint != null) {
                    val uid = cm.getConnectionOwnerUid(android.system.OsConstants.IPPROTO_TCP, remoteEndpoint, localEndpoint)
                    if (uid != -1 && uid != 0 && uid != android.os.Process.myUid()) {
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
            
            val intensity = ProxyStats.censorshipIntensity.value
            // 3. Adaptive SOCKS5 Handshake Jitter to defeat protocol timing analysis
            if (intensity > 60) {
                val jitter = if (intensity > 90) ThreadLocalRandom.current().nextLong(20, 100) else ThreadLocalRandom.current().nextLong(5, 25)
                delay(jitter)
            }
            
            val activeHost = host ?: ""
            val forcedStrategy = if (com.aistudio.pinkproxy.fresh.BypassConfig.isHostDirect(activeHost)) com.aistudio.pinkproxy.fresh.BypassStrategy.DIRECT else null
            
            TcpTransportHandler.handleTcpSession(
                clientSocket = client,
                targetHost = activeHost,
                targetPort = targetPort,
                vpnService = vpnService,
                scope = scope,
                forcedStrategy = forcedStrategy,
                onConnectSuccess = {
                    client.soTimeout = 0 // Remove timeout for the tunneled connection
                    try { client.keepAlive = true } catch (e: Throwable) {}
                    output.write(SOCKS5_CONNECT_SUCCESS)
                    output.flush()
                },
                onConnectFailure = { reason ->
                    try {
                        val errByte = when (reason) {
                            "DNS_FAILED" -> 4.toByte() // Host unreachable
                            "BYPASS_FAILED_STRICT" -> 5.toByte() // Connection refused
                            else -> 1.toByte() // General SOCKS server failure
                        }
                        output.write(byteArrayOf(5, errByte, 0, 1, 0, 0, 0, 0, 0, 0))
                        output.flush()
                    } catch (e: Throwable) {
                        Log.v("PinkProxy", "Failed to send SOCKS5 error response: ${e.message}")
                    }
                }
            )

        } catch (e: Throwable) {
            if (e is kotlinx.coroutines.CancellationException) throw e
            if (e !is java.io.EOFException && e !is java.net.SocketException) {
                Log.e("PinkProxy", "Client handling error from ${client.remoteSocketAddress}", e)
            } else {
                Log.v("PinkProxy", "Client disconnected: ${e.message}")
            }
        } finally {
            try { client.close() } catch (ex: Throwable) {
                Log.v("PinkProxy", "Failed to close client: ${ex.message}")
            }
        }
    }
}
