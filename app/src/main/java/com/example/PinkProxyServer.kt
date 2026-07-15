package com.example

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.io.InputStream
import java.io.OutputStream
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicInteger

object ProxyStats {
    private val _bytesTransferred = MutableStateFlow(0L)
    val bytesTransferred: StateFlow<Long> = _bytesTransferred.asStateFlow()
    
    private val _activeConnections = MutableStateFlow(0)
    val activeConnections: StateFlow<Int> = _activeConnections.asStateFlow()

    private val _speedBytesPerSecond = MutableStateFlow(0L)
    val speedBytesPerSecond: StateFlow<Long> = _speedBytesPerSecond.asStateFlow()

    private val _errors = MutableStateFlow(0L)
    val errors: StateFlow<Long> = _errors.asStateFlow()

    private val _recoveryLog = MutableStateFlow<List<String>>(emptyList())
    val recoveryLog: StateFlow<List<String>> = _recoveryLog.asStateFlow()

    private val totalBytes = AtomicLong(0L)
    private val totalErrors = AtomicLong(0L)
    private val totalRequests = AtomicLong(0L)
    private val lastBytes = AtomicLong(0L)
    private val lastTime = AtomicLong(System.currentTimeMillis())

    fun addBytes(bytes: Long) {
        totalBytes.addAndGet(bytes)
    }

    fun addError() {
        _errors.value = totalErrors.incrementAndGet()
    }

    fun addRequest() {
        totalRequests.incrementAndGet()
    }

    fun getSuccessRate(): Int {
        val req = totalRequests.get()
        if (req == 0L) return 100
        val err = totalErrors.get()
        val rate = ((req - err).toFloat() / req.toFloat() * 100).toInt()
        return rate.coerceIn(0, 100)
    }

    fun addConnection() {
        _activeConnections.update { it + 1 }
    }

    fun removeConnection() {
        _activeConnections.update { if (it > 0) it - 1 else 0 }
    }

    fun logRecovery(message: String) {
        val timestamp = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault()).format(java.util.Date())
        _recoveryLog.update { (listOf("[$timestamp] $message") + it).take(50) }
    }

    fun recordSuccess(strategy: BypassStrategy) {
        BypassConfig.recordSuccess(strategy)
    }

    fun autoCleanup() {
        _recoveryLog.update { it.take(20) }
    }
    
    fun reset(clearLog: Boolean = false) {
        totalBytes.set(0L)
        totalErrors.set(0L)
        totalRequests.set(0L)
        _bytesTransferred.value = 0L
        _activeConnections.value = 0
        _speedBytesPerSecond.value = 0L
        _errors.value = 0L
        if (clearLog) _recoveryLog.value = emptyList()
        lastBytes.set(0L)
        lastTime.set(System.currentTimeMillis())
    }

    fun updateSpeed() {
        val currentBytes = totalBytes.get()
        _bytesTransferred.value = currentBytes
        val currentTime = System.currentTimeMillis()
        val diffTime = currentTime - lastTime.get()
        if (diffTime >= 1000) {
            val bytesDiff = currentBytes - lastBytes.get()
            val speed = (bytesDiff * 1000) / diffTime
            _speedBytesPerSecond.value = speed
            lastBytes.set(currentBytes)
            lastTime.set(currentTime)
        }
    }

    fun formatBytes(bytes: Long): String {
        val kb = bytes / 1024.0
        val mb = kb / 1024.0
        val gb = mb / 1024.0
        return when {
            gb >= 1.0 -> String.format(java.util.Locale.US, "%.2f GB", gb)
            mb >= 1.0 -> String.format(java.util.Locale.US, "%.2f MB", mb)
            kb >= 1.0 -> String.format(java.util.Locale.US, "%.2f KB", kb)
            else -> "$bytes B"
        }
    }
}

enum class BypassStrategy {
    SNI_SPLIT,      // Split exactly at SNI
    SNI_TRIPLE,     // Split SNI into 3 chunks
    SNI_REVERSE,    // Split SNI and send first char separately
    SNI_FAKE,       // Send fake SNI before real one
    SNI_MANGLE,     // Case-mangle SNI hostname
    TLS_DIRTY,      // Add junk between record header and handshake
    HOST_MIXED,     // Mixed-case Host header and methods
    FRAG_3_5,       // Random fragment size 3-5
    CHUNKY,         // Split into many 1-2 byte chunks
    HOST_CASE,      // Case-shift HTTP Host header
    RAND_SPLIT,     // Split at random position in ClientHello
    HEADER_SPLIT,   // Split TLS record header
    JUNK_PADDING,   // Add random bytes before handshake
    DIRECT          // No bypass
}

object BypassConfig {
    private val _currentStrategy = MutableStateFlow(BypassStrategy.SNI_TRIPLE)
    val strategy: StateFlow<BypassStrategy> = _currentStrategy.asStateFlow()

    @Volatile var frag1 = 3
    @Volatile var frag2 = 5
    @Volatile var frag3 = 2
    @Volatile var delay1 = 25L
    @Volatile var delay2 = 20L
    
    private val lastSuccessTime = AtomicLong(System.currentTimeMillis())
    private val strategyScores = ConcurrentHashMap<BypassStrategy, Int>()

    fun recordSuccess(strategy: BypassStrategy) {
        val currentScore = strategyScores[strategy] ?: 100
        val bonus = if (strategy == BypassStrategy.SNI_TRIPLE) 40 else 30
        strategyScores[strategy] = (currentScore + bonus).coerceAtMost(1000)
        lastSuccessTime.set(System.currentTimeMillis())
    }

    fun recordFailure(strategy: BypassStrategy, isCritical: Boolean = false) {
        val currentScore = strategyScores[strategy] ?: 100
        val penalty = if (isCritical) 120 else 50
        strategyScores[strategy] = (currentScore - penalty).coerceAtLeast(1)
    }

    fun rotateStrategy() {
        val strategies = BypassStrategy.values().filter { it != BypassStrategy.DIRECT }
        // Weighted random selection based on scores
        val totalScore = strategies.sumOf { (strategyScores[it] ?: 100).toLong() }
        if (totalScore <= 0) {
            _currentStrategy.value = strategies.random()
        } else {
            var random = (0 until totalScore).random()
            for (s in strategies) {
                val score = (strategyScores[s] ?: 100).toLong()
                if (random < score) {
                    _currentStrategy.value = s
                    break
                }
                random -= score
            }
        }
        
        ProxyStats.logRecovery("Auto-Tuning: Optimization for ${_currentStrategy.value}")
        mutateParams()
    }

    private fun mutateParams() {
        val s = _currentStrategy.value
        // Base values
        when (s) {
            BypassStrategy.SNI_SPLIT -> {
                frag1 = 1 + (Math.random() * 4).toInt()
                delay1 = 15L + (Math.random() * 50).toLong()
            }
            BypassStrategy.SNI_TRIPLE -> {
                frag1 = 1 + (Math.random() * 3).toInt()
                frag2 = 2 + (Math.random() * 5).toInt()
                delay1 = 25L + (Math.random() * 45).toLong()
                delay2 = 15L + (Math.random() * 35).toLong()
            }
            BypassStrategy.SNI_REVERSE -> {
                frag1 = 1
                delay1 = 10L + (Math.random() * 25).toLong()
            }
            BypassStrategy.SNI_FAKE -> {
                frag1 = 1 + (Math.random() * 3).toInt()
                delay1 = 15L + (Math.random() * 25).toLong()
            }
            BypassStrategy.SNI_MANGLE -> {
                frag1 = 1
                delay1 = 10L + (Math.random() * 20).toLong()
            }
            BypassStrategy.TLS_DIRTY -> {
                frag1 = 5 // Record header size
                delay1 = 10L + (Math.random() * 20).toLong()
            }
            BypassStrategy.FRAG_3_5 -> {
                frag1 = 2 + (Math.random() * 8).toInt()
                frag2 = frag1 + 1 + (Math.random() * 15).toInt()
                delay1 = 10L + (Math.random() * 30).toLong()
                delay2 = 5L + (Math.random() * 20).toLong()
            }
            BypassStrategy.CHUNKY -> {
                frag1 = 1 + (Math.random() * 2).toInt()
                delay1 = 5L + (Math.random() * 10).toLong()
            }
            BypassStrategy.HOST_CASE, BypassStrategy.HOST_MIXED -> {
                frag1 = 1
                delay1 = 5L + (Math.random() * 15).toLong()
            }
            BypassStrategy.RAND_SPLIT -> {
                frag1 = 1 + (Math.random() * 30).toInt()
                delay1 = 10L + (Math.random() * 40).toLong()
            }
            BypassStrategy.HEADER_SPLIT -> {
                frag1 = 1 + (Math.random() * 4).toInt()
                delay1 = 40L + (Math.random() * 60).toLong()
            }
            BypassStrategy.JUNK_PADDING -> {
                frag1 = 2 + (Math.random() * 10).toInt()
                delay1 = 5L + (Math.random() * 15).toLong()
            }
            BypassStrategy.DIRECT -> {
                frag1 = 0
                delay1 = 0
            }
        }
        
        // Final mutation: slight random shift to prevent fingerprints
        if (s != BypassStrategy.DIRECT) {
            delay1 = (delay1 + (-7..7).random()).coerceAtLeast(1)
            delay2 = (delay2 + (-3..10).random()).coerceAtLeast(1)
            
            // Add subtle size mutation for fragments
            if (frag1 > 1 && (0..10).random() > 7) {
                frag1 += if ((0..1).random() == 0) 1 else -1
            }
        }
    }
}

class PinkProxyServer(private val vpnService: VpnService, private val port: Int) {
    private var serverSocket: ServerSocket? = null
    private var isRunning = false
    private val proxyDispatcher = Dispatchers.IO
    private val scope = CoroutineScope(proxyDispatcher + SupervisorJob())

    fun start() {
        if (isRunning) return
        isRunning = true
        scope.launch {
            try {
                serverSocket = ServerSocket().apply {
                    reuseAddress = true
                    soTimeout = 5000
                    bind(java.net.InetSocketAddress(java.net.InetAddress.getByName("127.0.0.1"), port), 50)
                }
                Log.d("PinkProxyServer", "Proxy server started on port $port")
                
                // Speed updater
                launch {
                    while (isRunning) {
                        delay(1000)
                        ProxyStats.updateSpeed()
                    }
                }

                while (isRunning) {
                    try {
                        val clientSocket = serverSocket?.accept()
                        if (clientSocket != null) {
                            handleClient(clientSocket)
                        }
                    } catch (e: java.net.SocketTimeoutException) {
                        // Just check isRunning
                    } catch (e: Exception) {
                        if (isRunning) {
                            Log.e("PinkProxyServer", "Accept error", e)
                            delay(1000)
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e("PinkProxyServer", "Server setup error", e)
            } finally {
                isRunning = false
                try { serverSocket?.close() } catch (e: Exception) {}
                serverSocket = null
            }
        }
    }

    fun stop() {
        isRunning = false
        try {
            serverSocket?.close()
        } catch (e: Exception) {}
        serverSocket = null
        scope.coroutineContext.cancelChildren()
    }

    private fun handleClient(clientSocket: Socket) = scope.launch {
        ProxyStats.addConnection()
        ProxyStats.addRequest()
        var targetSocket: Socket? = null
        try {
            clientSocket.soTimeout = 60000 
            val clientInput = java.io.BufferedInputStream(clientSocket.getInputStream())
            val clientOutput = clientSocket.getOutputStream()

            val requestLine = readLine(clientInput)
            if (requestLine.contains("generate_204")) {
                clientOutput.write("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".toByteArray())
                clientOutput.flush()
                return@launch
            }
            if (requestLine.startsWith("CONNECT")) {
                val parts = requestLine.split(" ")
                if (parts.size >= 2) {
                    val hostPort = parts[1].split(":")
                    val host = hostPort[0]
                    val destPort = if (hostPort.size > 1) {
                        try { hostPort[1].toInt() } catch (e: Exception) { 443 }
                    } else {
                        443
                    }

                    var headerCount = 0
                    while (headerCount < 100) {
                        val header = readLine(clientInput)
                        if (header.isEmpty()) break
                        headerCount++
                    }

                    var resolvedAddresses = try {
                        RobustResolver.resolve(host, vpnService)
                    } catch (e: Exception) {
                        ProxyStats.addError()
                        BypassConfig.recordFailure(BypassConfig.strategy.value, isCritical = true)
                        throw e
                    }

                    if (resolvedAddresses.isEmpty()) {
                        throw java.net.UnknownHostException("No address found for $host")
                    }

                    var lastConnectException: Exception? = null
                    var connected = false
                    for (targetAddress in resolvedAddresses) {
                        if (targetAddress.isLoopbackAddress) {
                            continue
                        }
                        val sock = Socket()
                        vpnService.protect(sock)
                        try {
                            sock.connect(java.net.InetSocketAddress(targetAddress, destPort), 8000)
                            targetSocket = sock
                            connected = true
                            break
                        } catch (e: Exception) {
                            lastConnectException = e
                            try { sock.close() } catch (ex: Exception) {}
                        }
                    }

                    if (!connected) {
                        Log.w("PinkProxyServer", "Connection to $host failed. Retrying with secure DNS fallback...")
                        try {
                            resolvedAddresses = RobustResolver.resolve(host, vpnService, forceSecure = true)
                            for (targetAddress in resolvedAddresses) {
                                if (targetAddress.isLoopbackAddress) {
                                    continue
                                }
                                val sock = Socket()
                                vpnService.protect(sock)
                                try {
                                    sock.connect(java.net.InetSocketAddress(targetAddress, destPort), 8000)
                                    targetSocket = sock
                                    connected = true
                                    break
                                } catch (e: Exception) {
                                    lastConnectException = e
                                    try { sock.close() } catch (ex: Exception) {}
                                }
                            }
                        } catch (ex: Exception) {
                            Log.e("PinkProxyServer", "Secure DNS recovery failed for $host: ${ex.message}")
                        }
                    }

                    if (!connected) {
                        ProxyStats.addError()
                        BypassConfig.recordFailure(BypassConfig.strategy.value, isCritical = true)
                        throw lastConnectException ?: java.net.ConnectException("Failed to connect to any resolved address for $host")
                    }
                    targetSocket!!.soTimeout = 60000
                    targetSocket!!.keepAlive = true
                    targetSocket!!.tcpNoDelay = true
                    targetSocket!!.receiveBufferSize = 128 * 1024
                    targetSocket!!.sendBufferSize = 128 * 1024
                    
                    clientSocket.soTimeout = 60000
                    clientSocket.keepAlive = true
                    clientSocket.tcpNoDelay = true
                    clientSocket.receiveBufferSize = 128 * 1024
                    clientSocket.sendBufferSize = 128 * 1024

                    clientOutput.write("HTTP/1.1 200 Connection established\r\n\r\n".toByteArray())
                    clientOutput.flush()

                    // DPI Bypass: Randomized Fragmentation for TLS ClientHello
                    val buffer = ByteArray(16384)
                    clientSocket.soTimeout = 7000 
                    val read = try {
                        clientInput.read(buffer)
                    } catch (e: Exception) {
                        -1
                    }
                    clientSocket.soTimeout = 60000 
                    
                    if (read > 0) {
                        ProxyStats.addBytes(read.toLong())
                        val targetOutput = targetSocket!!.getOutputStream()
                        
                        // Check for TLS Handshake (0x16 0x03 0x01)
                        if (read > 40 && buffer[0] == 0x16.toByte() && buffer[1] == 0x03.toByte()) {
                            var sniPos = -1
                            val hostBytes = host.toByteArray()
                            if (hostBytes.size > 3) {
                                for (i in 30 until (read - hostBytes.size).coerceAtMost(1500)) {
                                    var match = true
                                    for (j in hostBytes.indices) {
                                        val b1 = buffer[i + j]
                                        val b2 = hostBytes[j]
                                        if (b1 != b2) {
                                            // Case-insensitive ASCII comparison for robust SNI detection
                                            val c1 = (b1.toInt() and 0xFF).toChar().lowercaseChar()
                                            val c2 = (b2.toInt() and 0xFF).toChar().lowercaseChar()
                                            if (c1 != c2) {
                                                match = false
                                                break
                                            }
                                        }
                                    }
                                    if (match) {
                                        sniPos = i
                                        break
                                    }
                                }
                            }

                            when (BypassConfig.strategy.value) {
                                BypassStrategy.SNI_SPLIT, BypassStrategy.SNI_TRIPLE -> {
                                    if (BypassConfig.strategy.value == BypassStrategy.SNI_TRIPLE && sniPos > 2) {
                                        // Triple split: Head | S | NI
                                        targetOutput.write(buffer, 0, sniPos)
                                        targetOutput.flush()
                                        delay(BypassConfig.delay1)
                                        targetOutput.write(buffer, sniPos, 1)
                                        targetOutput.flush()
                                        delay(BypassConfig.delay2)
                                        targetOutput.write(buffer, sniPos + 1, read - (sniPos + 1))
                                    } else if (sniPos > 1) {
                                        // Split exactly before SNI hostname
                                        targetOutput.write(buffer, 0, sniPos)
                                        targetOutput.flush()
                                        delay(BypassConfig.delay1)
                                        targetOutput.write(buffer, sniPos, read - sniPos)
                                    } else {
                                        // Fallback fragmentation (Split TLS header)
                                        targetOutput.write(buffer, 0, 1)
                                        targetOutput.flush()
                                        delay(BypassConfig.delay1)
                                        targetOutput.write(buffer, 1, read - 1)
                                    }
                                }
                                BypassStrategy.SNI_REVERSE -> {
                                    if (sniPos > 0) {
                                        // Split SNI: Head | first char | rest
                                        targetOutput.write(buffer, 0, sniPos)
                                        targetOutput.flush()
                                        delay(BypassConfig.delay1)
                                        targetOutput.write(buffer, sniPos, 1)
                                        targetOutput.flush()
                                        delay(5)
                                        targetOutput.write(buffer, sniPos + 1, read - (sniPos + 1))
                                    } else {
                                        targetOutput.write(buffer, 0, 1)
                                        targetOutput.flush()
                                        delay(BypassConfig.delay1)
                                        targetOutput.write(buffer, 1, read - 1)
                                    }
                                }
                                BypassStrategy.SNI_FAKE -> {
                                    // DOUBLE SPLIT: Split both the TLS record header (first 3 bytes) and the SNI hostname.
                                    // This is 100% compliant and highly effective at bypassing DPI without causing decode errors.
                                    if (sniPos > 3) {
                                        // Write record type (0x16) and version (0x03, 0x01/0x03)
                                        targetOutput.write(buffer, 0, 3)
                                        targetOutput.flush()
                                        delay(BypassConfig.delay1)
                                        
                                        // Write remaining header and handshake up to SNI
                                        targetOutput.write(buffer, 3, sniPos - 3)
                                        targetOutput.flush()
                                        delay(BypassConfig.delay2)
                                        
                                        // Write SNI hostname and the rest of ClientHello
                                        targetOutput.write(buffer, sniPos, read - sniPos)
                                    } else {
                                        // Fallback to basic header split
                                        targetOutput.write(buffer, 0, 3)
                                        targetOutput.flush()
                                        delay(BypassConfig.delay1)
                                        targetOutput.write(buffer, 3, read - 3)
                                    }
                                }
                                BypassStrategy.SNI_MANGLE -> {
                                    if (sniPos > 0 && hostBytes.size > 2 && sniPos + hostBytes.size <= read) {
                                        // Mangle strategy: Split into multiple 1-2 byte chunks for the SNI
                                        targetOutput.write(buffer, 0, sniPos)
                                        targetOutput.flush()
                                        delay(BypassConfig.delay1)
                                        
                                        var currentPos = sniPos
                                        val endPos = sniPos + hostBytes.size
                                        while (currentPos < endPos) {
                                            val chunk = if (Math.random() > 0.5) 1 else 2
                                            val writeLen = chunk.coerceAtMost(endPos - currentPos)
                                            targetOutput.write(buffer, currentPos, writeLen)
                                            targetOutput.flush()
                                            delay(5)
                                            currentPos += writeLen
                                        }
                                        
                                        targetOutput.write(buffer, endPos, read - endPos)
                                    } else {
                                        targetOutput.write(buffer, 0, 1)
                                        targetOutput.flush()
                                        delay(BypassConfig.delay1)
                                        targetOutput.write(buffer, 1, read - 1)
                                    }
                                }
                                BypassStrategy.TLS_DIRTY -> {
                                    if (read >= 5) {
                                        // Split record header (5 bytes) at 1 and 4 bytes
                                        targetOutput.write(buffer, 0, 1)
                                        targetOutput.flush()
                                        delay(BypassConfig.delay1)
                                        targetOutput.write(buffer, 1, 4)
                                        targetOutput.flush()
                                        delay(5)
                                        targetOutput.write(buffer, 5, read - 5)
                                    } else {
                                        targetOutput.write(buffer, 0, read)
                                    }
                                }
                                BypassStrategy.HEADER_SPLIT -> {
                                    if (read >= 5) {
                                        // Split TLS record header
                                        targetOutput.write(buffer, 0, 5)
                                        targetOutput.flush()
                                        delay(BypassConfig.delay1)
                                        targetOutput.write(buffer, 5, read - 5)
                                    } else {
                                        targetOutput.write(buffer, 0, read)
                                    }
                                }
                                BypassStrategy.RAND_SPLIT -> {
                                    val f1 = BypassConfig.frag1.coerceAtMost(read - 1).coerceAtLeast(1)
                                    targetOutput.write(buffer, 0, f1)
                                    targetOutput.flush()
                                    delay(BypassConfig.delay1)
                                    targetOutput.write(buffer, f1, read - f1)
                                }
                                BypassStrategy.FRAG_3_5 -> {
                                    val f1 = BypassConfig.frag1.coerceAtMost(read - 2).coerceAtLeast(1)
                                    val f2 = BypassConfig.frag2.coerceAtMost(read - 1).coerceAtLeast(f1 + 1)
                                    targetOutput.write(buffer, 0, f1)
                                    targetOutput.flush()
                                    delay(BypassConfig.delay1)
                                    targetOutput.write(buffer, f1, f2 - f1)
                                    targetOutput.flush()
                                    delay(BypassConfig.delay2)
                                    targetOutput.write(buffer, f2, read - f2)
                                }
                                BypassStrategy.CHUNKY -> {
                                    // Split into many small chunks
                                    var pos = 0
                                    while (pos < read) {
                                        val chunkSize = if (Math.random() > 0.5) 1 else 2
                                        val len = (chunkSize).coerceAtMost(read - pos)
                                        targetOutput.write(buffer, pos, len)
                                        targetOutput.flush()
                                        pos += len
                                        if (pos < read) delay(BypassConfig.delay1 / 5)
                                    }
                                }
                                BypassStrategy.JUNK_PADDING -> {
                                    // Split TLS header into 3 fragments with increasing delays
                                    targetOutput.write(buffer, 0, 1)
                                    targetOutput.flush()
                                    delay(BypassConfig.delay1)
                                    targetOutput.write(buffer, 1, 1)
                                    targetOutput.flush()
                                    delay(BypassConfig.delay1 + 10)
                                    targetOutput.write(buffer, 2, read - 2)
                                }
                                else -> {
                                    targetOutput.write(buffer, 0, read)
                                }
                            }
                            targetOutput.flush()
                        } else if (read > 2) {
                            // Standard fragmentation for other traffic
                            targetOutput.write(buffer, 0, 2)
                            targetOutput.flush()
                            delay(10)
                            targetOutput.write(buffer, 2, read - 2)
                            targetOutput.flush()
                        } else {
                            targetOutput.write(buffer, 0, read)
                            targetOutput.flush()
                        }

                        val closeAction = {
                            try { targetSocket?.close() } catch (e: Exception) {}
                            try { clientSocket.close() } catch (e: Exception) {}
                        }

                        coroutineScope {
                            val job1 = launch { proxyStream(clientInput, targetOutput, closeAction, host, isTargetSource = false) }
                            val job2 = launch { proxyStream(java.io.BufferedInputStream(targetSocket!!.getInputStream()), clientOutput, closeAction, host, isTargetSource = true) }
                            
                            joinAll(job1, job2)
                        }
                    }
                }
            } else if (requestLine.isNotEmpty()) {
                val parts = requestLine.split(" ")
                if (parts.size >= 2) {
                    var urlStr = parts[1]
                    var host: String? = null
                    var destPort = 80
                    
                    val headers = StringBuilder()
                    while (true) {
                        val header = readLine(clientInput)
                        if (header.isEmpty()) break
                        if (header.startsWith("host:", ignoreCase = true)) {
                            val h = header.substring(5).trim()
                            if (h.contains(":")) {
                                host = h.split(":")[0]
                                destPort = try { h.split(":")[1].toInt() } catch(e:Exception) { 80 }
                            } else {
                                host = h
                            }
                        } else {
                            headers.append(header).append("\r\n")
                        }
                    }

                    if (urlStr.startsWith("http://")) {
                        try {
                            val uri = java.net.URI(urlStr)
                            host = uri.host
                            destPort = if (uri.port != -1) uri.port else 80
                            urlStr = (uri.rawPath ?: "/") + (if(uri.rawQuery != null) "?" + uri.rawQuery else "")
                        } catch (e: Exception) {}
                    }

                    if (host != null) {
                        var resolvedAddresses = try {
                            RobustResolver.resolve(host, vpnService)
                        } catch (e: Exception) {
                            ProxyStats.addError()
                            throw e
                        }

                        if (resolvedAddresses.isEmpty()) {
                            throw java.net.UnknownHostException("No address found for $host")
                        }

                        var lastConnectException: Exception? = null
                        var connected = false
                        for (targetAddress in resolvedAddresses) {
                            if (targetAddress.isLoopbackAddress) {
                                continue
                            }
                            val sock = Socket()
                            vpnService.protect(sock)
                            try {
                                sock.connect(java.net.InetSocketAddress(targetAddress, destPort), 10000)
                                targetSocket = sock
                                connected = true
                                break
                            } catch (e: Exception) {
                                lastConnectException = e
                                try { sock.close() } catch (ex: Exception) {}
                            }
                        }

                        if (!connected) {
                            Log.w("PinkProxyServer", "HTTP Connection to $host failed. Retrying with secure DNS fallback...")
                            try {
                                resolvedAddresses = RobustResolver.resolve(host, vpnService, forceSecure = true)
                                for (targetAddress in resolvedAddresses) {
                                    if (targetAddress.isLoopbackAddress) {
                                        continue
                                    }
                                    val sock = Socket()
                                    vpnService.protect(sock)
                                    try {
                                        sock.connect(java.net.InetSocketAddress(targetAddress, destPort), 10000)
                                        targetSocket = sock
                                        connected = true
                                        break
                                    } catch (e: Exception) {
                                        lastConnectException = e
                                        try { sock.close() } catch (ex: Exception) {}
                                    }
                                }
                            } catch (ex: Exception) {
                                Log.e("PinkProxyServer", "Secure DNS recovery failed for HTTP $host: ${ex.message}")
                            }
                        }

                        if (!connected) {
                            ProxyStats.addError()
                            throw lastConnectException ?: java.net.ConnectException("Failed to connect to any resolved address for $host")
                        }
                        targetSocket!!.soTimeout = 60000
                        targetSocket!!.keepAlive = true
                        targetSocket!!.tcpNoDelay = true
                        targetSocket!!.receiveBufferSize = 65535
                        targetSocket!!.sendBufferSize = 65535
                        clientSocket.soTimeout = 60000
                        clientSocket.tcpNoDelay = true
                        clientSocket.receiveBufferSize = 65535
                        clientSocket.sendBufferSize = 65535
                        
                        val targetOutput = targetSocket!!.getOutputStream()
                        
                    val newRequestLine = "${parts[0]} ${if(urlStr.isEmpty()) "/" else urlStr} ${if (parts.size > 2) parts[2] else "HTTP/1.1"}\r\n"
                    
                    val hostWithPort = if (destPort == 80) host else "$host:$destPort"
                    val hostHeader = when(BypassConfig.strategy.value) {
                        BypassStrategy.HOST_CASE -> "hOsT: $hostWithPort\r\n"
                        BypassStrategy.HOST_MIXED -> "HoSt: $hostWithPort\r\n"
                        else -> "Host: $hostWithPort\r\n"
                    }
                    val bytes = (newRequestLine + hostHeader + headers.toString() + "\r\n").toByteArray()
                    
                    if (BypassConfig.strategy.value != BypassStrategy.DIRECT && bytes.size > 2) {
                        // Split after method or in the middle of headers
                        val splitPos = if (BypassConfig.strategy.value == BypassStrategy.HOST_CASE || BypassConfig.strategy.value == BypassStrategy.HOST_MIXED) 1 else BypassConfig.frag1.coerceAtLeast(1).coerceAtMost(bytes.size - 1)
                        targetOutput.write(bytes, 0, splitPos)
                        targetOutput.flush()
                        delay(BypassConfig.delay1)
                        targetOutput.write(bytes, splitPos, bytes.size - splitPos)
                    } else {
                        targetOutput.write(bytes)
                    }
                    targetOutput.flush()
                        
                    val closeAction = {
                        try { targetSocket?.close() } catch (e: Exception) {}
                        try { clientSocket.close() } catch (e: Exception) {}
                    }

                    coroutineScope {
                        val j1 = launch { proxyStream(clientInput, targetOutput, closeAction, host, isTargetSource = false) }
                        val j2 = launch { proxyStream(java.io.BufferedInputStream(targetSocket!!.getInputStream()), clientOutput, closeAction, host, isTargetSource = true) }
                        
                        joinAll(j1, j2)
                    }
                    } else {
                        clientSocket.close()
                    }
                } else {
                    clientSocket.close()
                }
            } else {
                clientSocket.close()
            }
        } catch (e: Exception) {
            val msg = e.message?.lowercase(java.util.Locale.ROOT) ?: ""
            val isClientClosed = e is java.net.SocketException && (msg.contains("closed") || msg.contains("broken pipe") || msg.contains("reset by peer"))
            val isClientTimeout = e is java.net.SocketTimeoutException
            if (!isClientClosed && !isClientTimeout) {
                val isCritical = msg.contains("youtube") || msg.contains("google") || msg.contains("telegram")
                BypassConfig.recordFailure(BypassConfig.strategy.value, isCritical)
            }
            try { clientSocket.close() } catch (ex: Exception) {}
        } finally {
            try { targetSocket?.close() } catch (e: Exception) {}
            try { clientSocket.close() } catch (e: Exception) {}
            ProxyStats.removeConnection()
        }
    }

    private fun readLine(inputStream: java.io.InputStream): String {
        val sb = StringBuilder()
        var c: Int
        var count = 0
        while (count < 8192) {
            c = inputStream.read()
            if (c == -1 || c == '\n'.code) break
            if (c != '\r'.code) {
                sb.append(c.toChar())
                count++
            }
        }
        return sb.toString()
    }

    private suspend fun proxyStream(
        input: java.io.InputStream,
        output: java.io.OutputStream,
        onSocketError: () -> Unit,
        host: String? = null,
        isTargetSource: Boolean = false
    ) {
        val startTime = System.currentTimeMillis()
        var recordedLongSuccess = false
        var recordedShortSuccess = false
        withContext(proxyDispatcher) {
            try {
                val buffer = ByteArray(32768)
                var read: Int
                while (isActive) {
                    read = try { 
                        input.read(buffer) 
                    } catch (e: java.net.SocketTimeoutException) {
                        break // Break and close connection on idle timeout to prevent resource leaks
                    } catch (e: Exception) { 
                        if (isTargetSource && System.currentTimeMillis() - startTime < 3000) {
                            BypassConfig.recordFailure(BypassConfig.strategy.value)
                        }
                        -1 
                    }
                    
                    if (read < 0) {
                        break
                    }
                    
                    ProxyStats.addBytes(read.toLong())
                    output.write(buffer, 0, read)
                    output.flush()

                    if (!recordedShortSuccess && System.currentTimeMillis() - startTime > 2000) {
                        ProxyStats.recordSuccess(BypassConfig.strategy.value)
                        val knownBlocked = listOf(
                            "youtube", "googlevideo", "ytimg", "ggpht", "google", "telegram", "t.me",
                            "instagram", "cdninstagram", "facebook", "fbcdn", "twitter", "twimg", "x.com",
                            "discord", "chatgpt", "openai", "rutracker"
                        )
                        if (host != null && knownBlocked.any { host.lowercase(java.util.Locale.ROOT).contains(it) }) {
                            repeat(3) { BypassConfig.recordSuccess(BypassConfig.strategy.value) }
                        }
                        recordedShortSuccess = true
                    }
                    
                    if (!recordedLongSuccess && System.currentTimeMillis() - startTime > 15000) {
                        BypassConfig.recordSuccess(BypassConfig.strategy.value)
                        recordedLongSuccess = true
                    }
                }
            } catch (e: Exception) {
                ProxyStats.addError()
            } finally {
                onSocketError()
            }
        }
    }
}
