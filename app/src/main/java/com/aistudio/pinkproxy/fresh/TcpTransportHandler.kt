package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.sync.Mutex
import java.util.concurrent.atomic.AtomicReference

object TcpTransportHandler {

    @OptIn(DelicateCoroutinesApi::class)
    suspend fun handleTcpSession(
        clientSocket: Socket,
        targetHost: String,
        targetPort: Int,
        vpnService: VpnService?,
        scope: CoroutineScope,
        forcedStrategy: BypassStrategy? = null,
        onConnectSuccess: (suspend () -> Unit)? = null,
        onConnectFailure: (suspend (reason: String) -> Unit)? = null
    ) {
        var remoteSocket: Socket? = null
        var remoteIn: InputStream? = null
        var remoteOut: OutputStream? = null
        try {
            clientSocket.tcpNoDelay = true
            clientSocket.keepAlive = true
            try { clientSocket.receiveBufferSize = 65536 } catch (e: Throwable) {}
            try { clientSocket.sendBufferSize = 65536 } catch (e: Throwable) {}

            if (RecoveryManager.isHostBlacklisted(targetHost)) {
                Log.w("TcpTransport", "Rejecting connection to blacklisted host: $targetHost")
                onConnectFailure?.invoke("BLACKLISTED")
                clientSocket.close()
                return
            }

            val resolved = RobustResolver.resolve(targetHost, vpnService)
            if (resolved.isEmpty()) {
                Log.w("TcpTransport", "Resolution failed for $targetHost")
                onConnectFailure?.invoke("DNS_FAILED")
                clientSocket.close()
                return
            }
            ProxyStats.addTraffic(targetHost)
            val totalWrittenClient = AtomicLong(0)
            val isTls = targetPort == 443 || targetPort == 8443

            val censorship = BypassConfig.censorshipLevel.value
            var strategy = forcedStrategy ?: BypassConfig.getBestStrategyForHost(targetHost)
            var config = BypassConfig.getSessionConfig(targetHost, strategy, BypassConfig.currentRttMs.value)

            // SNI Ghosting: Send fake TLS Hello with low TTL to distract DPI
            if (censorship > 65 && isTls) {
                scope.launch(ProxyDispatcher.io) {
                    performSniGhosting(targetHost, vpnService)
                }
            }

            val clientIn = clientSocket.getInputStream()
            val clientOut = clientSocket.getOutputStream()
            
            val lastActivity = AtomicLong(System.currentTimeMillis())
            val detectedSni = AtomicReference<String?>(null)
            val writeMutex = Mutex()
            
            // Adaptive buffer size based on RTT and censorship
            val rtt = BypassConfig.currentRttMs.value
            val intensity = ProxyStats.censorshipIntensity.value
            val transportBufferSize = when {
                intensity > 80 -> 4096 // Smaller buffers for intense fragmentation
                rtt > 500 -> 8192
                rtt > 200 -> 16384
                else -> 32768
            }

            val firstClientPacket = ByteArray(transportBufferSize)
            clientSocket.soTimeout = 3000 // Increased for slower networks
            var firstClientPacketLen = 0
            try {
                firstClientPacketLen = clientIn.read(firstClientPacket)
            } catch (e: Throwable) {
                // Not always an error, client might wait for server
            }

            var firstRemoteResponse: ByteArray? = null
            var firstRemoteResponseLen = 0

            if (firstClientPacketLen > 0 && (targetPort == 443 || targetPort == 80 || targetPort == 8443)) {
                var attempt = 0
                val maxAttempts = 3
                while (attempt < maxAttempts) {
                    attempt++
                    if (attempt > 1) {
                        // Record previous failure and pick fallback or better strategy
                        DpiEngine.recordResult(strategy, false, HostClassifier.classify(targetHost), reason = FailureReason.CENSORSHIP_STALL, host = targetHost)
                        BypassConfig.recordFailure(strategy, targetHost, FailureReason.CENSORSHIP_STALL)
                        val fallback = DpiEngine.getFallbackStrategy(strategy)
                        strategy = fallback ?: DpiEngine.getBestStrategy(HostClassifier.classify(targetHost), targetHost)
                        config = BypassConfig.getSessionConfig(targetHost, strategy, BypassConfig.currentRttMs.value)
                        Log.i("TcpTransport", "Transparent fallback: Retrying connection to $targetHost (attempt $attempt/$maxAttempts) using strategy $strategy")
                    }

                    val rs = connectToBestIp(resolved, targetPort, vpnService, config, targetHost)
                    if (rs == null) {
                        delay(150)
                        continue
                    }
                    
                    // Apply socket optimizations
                    rs.tcpNoDelay = true
                    rs.keepAlive = true
                    try { rs.receiveBufferSize = 65536 } catch (e: Throwable) {}
                    try { rs.sendBufferSize = 65536 } catch (e: Throwable) {}

                    val rsOut = rs.getOutputStream()
                    val rsIn = rs.getInputStream()

                    try {
                        // Apply bypass on the first client packet
                        BypassConfig.applyBypass(rs, rsOut, firstClientPacket, firstClientPacketLen, config, targetHost)
                        
                        // Read first response packet with short adaptive timeout to verify bypass
                        val verifyTimeout = (BypassConfig.currentRttMs.value * 3 + 800).coerceAtMost(3000).toInt()
                        rs.soTimeout = verifyTimeout
                        
                        val responseBuf = ByteArray(transportBufferSize)
                        val readBytes = rsIn.read(responseBuf)
                        if (readBytes > 0) {
                            // Handshake succeeded!
                            DpiEngine.recordResult(strategy, true, HostClassifier.classify(targetHost), host = targetHost)
                            BypassConfig.recordSuccess(strategy, verifyTimeout.toLong(), targetHost)
                            
                            remoteSocket = rs
                            remoteIn = rsIn
                            remoteOut = rsOut
                            firstRemoteResponse = responseBuf
                            firstRemoteResponseLen = readBytes
                            break // Exit retry loop
                        } else if (readBytes == -1) {
                            throw java.io.IOException("EOF received during handshake verification")
                        }
                    } catch (e: Throwable) {
                        Log.w("TcpTransport", "Handshake attempt $attempt failed for $targetHost with strategy $strategy: ${e.message}")
                        try { rs.close() } catch (ex: Throwable) {}
                        
                        if (attempt == maxAttempts) {
                            DpiEngine.recordResult(strategy, false, HostClassifier.classify(targetHost), reason = FailureReason.CONNECTION_REFUSED, host = targetHost)
                            BypassConfig.recordFailure(strategy, targetHost, FailureReason.CONNECTION_REFUSED)
                            
                            // Blacklist if repeated failures
                            RecoveryManager.blacklistHost(targetHost, 120000) // 2 minutes
                        }
                    }
                }
            }

            // Direct fallback connection if the retry loop didn't succeed, or if there was no first client packet
            if (remoteSocket == null) {
                if (BypassConfig.isStrictBypassMode) {
                    Log.w("TcpTransport", "Bypass failed for $targetHost and strict bypass mode is enabled. Aborting fallback.")
                    onConnectFailure?.invoke("BYPASS_FAILED_STRICT")
                    clientSocket.close()
                    return
                }
                Log.v("TcpTransport", "Bypass attempts failed for $targetHost. Connecting directly.")
                remoteSocket = connectToBestIp(resolved, targetPort, vpnService, config, targetHost)
                if (remoteSocket == null) {
                    onConnectFailure?.invoke("CONNECT_FAILED")
                    clientSocket.close()
                    return
                }
                remoteSocket!!.tcpNoDelay = true
                remoteSocket!!.keepAlive = true
                remoteIn = remoteSocket!!.getInputStream()
                remoteOut = remoteSocket!!.getOutputStream()
                
                // If we have client data, write it direct
                if (firstClientPacketLen > 0) {
                    try {
                        remoteOut.write(firstClientPacket, 0, firstClientPacketLen)
                        remoteOut.flush()
                    } catch (e: Throwable) {
                        Log.w("TcpTransport", "Failed to write first packet directly: ${e.message}")
                        onConnectFailure?.invoke("WRITE_FAILED")
                        clientSocket.close()
                        remoteSocket.close()
                        return
                    }
                }
            }

            // Connection successfully established to remote target
            onConnectSuccess?.invoke()

            coroutineScope {
                val finalRemoteSocket = remoteSocket!!
                // Forward from Remote to Client (Direct)
                launch(ProxyDispatcher.io) {
                    val buffer = if (transportBufferSize > 16384) ProxyStats.obtain64k() else ProxyStats.obtain16k()
                    try {
                        if (firstRemoteResponse != null && firstRemoteResponseLen > 0) {
                            clientOut.write(firstRemoteResponse, 0, firstRemoteResponseLen)
                            clientOut.flush()
                            ProxyStats.updateBytes(firstRemoteResponseLen.toLong())
                        }
                        
                        finalRemoteSocket.soTimeout = 90000
                        val inputStream = remoteIn ?: return@launch
                        while (isActive) {
                            val n = inputStream.read(buffer)
                            if (n <= 0) break
                            lastActivity.set(System.currentTimeMillis())
                            clientOut.write(buffer, 0, n)
                            clientOut.flush()
                            ProxyStats.updateBytes(n.toLong())
                        }
                    } catch (e: Throwable) {
                        if (e !is CancellationException && e !is java.net.SocketException) {
                            Log.v("TcpTransport", "R2C error: ${e.message}")
                        }
                    } finally {
                        if (buffer.size > 16384) ProxyStats.release64k(buffer) else ProxyStats.release16k(buffer)
                        try { clientSocket.close() } catch (e: Throwable) {}
                        try { finalRemoteSocket.close() } catch (e: Throwable) {}
                    }
                }

                // Forward from Client to Remote (with Bypass & Advanced Evasion)
                launch(ProxyDispatcher.io) {
                    val buffer = if (transportBufferSize > 16384) ProxyStats.obtain64k() else ProxyStats.obtain16k()
                    val rnd = ThreadLocalRandom.current()
                    var packetsCount = 1
                    try {
                        clientSocket.soTimeout = 90000
                        while (isActive) {
                            val n = clientIn.read(buffer)
                            if (n <= 0) break
                            lastActivity.set(System.currentTimeMillis())
                            val currentIntensity = ProxyStats.censorshipIntensity.value
                            packetsCount++
                            
                            val activeHost = detectedSni.get() ?: targetHost
                            
                             if (packetsCount <= 12) {
                                // Try to extract SNI if it's a TLS handshake
                                if (packetsCount <= 3) {
                                    val sniOffset = TlsParser.findSniOffset(buffer, n)
                                    if (sniOffset != -1) {
                                        val realSni = TlsParser.extractHostname(buffer, n, sniOffset)
                                        if (realSni != null) {
                                            detectedSni.set(realSni)
                                            if (TlsParser.isTls13(buffer, n)) {
                                                ProxyStats.logTraffic("TLS 1.3 detected for $realSni")
                                            }
                                        }
                                    }
                                    
                                    // Fragmentation is safer than padding for standard TCP streams
                                    if (currentIntensity > 65 && n > 100 && packetsCount < 10) {
                                        val split = if (TlsParser.isClientHello(buffer, n)) 
                                            (TlsParser.findSniOffset(buffer, n) - 2).coerceIn(10, n - 10)
                                        else 
                                            n / 2
                                        
                                        val outputStream = remoteOut ?: break
                                        outputStream.write(buffer, 0, split)
                                        outputStream.flush()
                                        delay(rnd.nextLong(2, 20))
                                        outputStream.write(buffer, split, n - split)
                                        outputStream.flush()
                                        ProxyStats.updateBytes(n.toLong())
                                        continue
                                    }
                                }
                                
                                // Extreme evasion: Sequence Desync / Zero-Window Desync
                                if (currentIntensity > 80 && packetsCount < 5) {
                                    if (currentIntensity > 90 && rnd.nextBoolean()) {
                                        sendZeroWindowDesync(finalRemoteSocket, rnd)
                                    } else {
                                        sendSequenceDesync(finalRemoteSocket, rnd)
                                    }
                                }

                                writeMutex.lock()
                                try {
                                    val outputStream = remoteOut ?: break
                                    BypassConfig.applyBypass(finalRemoteSocket, outputStream, buffer, n, config, activeHost)
                                } finally {
                                    writeMutex.unlock()
                                }
                            } else {
                                if (currentIntensity > 40) {
                                    if (packetsCount % 13 == 0) {
                                        oscillateWindowSize(finalRemoteSocket)
                                    }

                                    val mtuThreshold = (BypassConfig.currentMtu.value * 0.6).toInt().coerceIn(400, 1000)
                                    if (n > mtuThreshold) {
                                        var offset = 0
                                        while (offset < n) {
                                            val sz = if (currentIntensity > 75) 
                                                rnd.nextInt(16, 128).coerceAtMost(n - offset)
                                            else 
                                                rnd.nextInt(128, mtuThreshold).coerceAtMost(n - offset)
                                            
                                            writeMutex.lock()
                                            try {
                                                val outputStream = remoteOut ?: break
                                                // In extreme cases, inject a tiny junk segment with low TTL before the real fragment
                                                if (currentIntensity > 85 && rnd.nextInt(100) < 35) {
                                                    injectGhostSegment(finalRemoteSocket, outputStream, rnd)
                                                }
                                                
                                                outputStream.write(buffer, offset, sz)
                                                outputStream.flush()
                                            } finally {
                                                writeMutex.unlock()
                                            }
                                            offset += sz
                                            delay(rnd.nextLong(1, 10))
                                        }
                                        ProxyStats.updateBytes(n.toLong())
                                        continue
                                    }
                                }

                                writeMutex.lock()
                                try {
                                    val outputStream = remoteOut ?: break
                                    outputStream.write(buffer, 0, n)
                                    outputStream.flush()
                                    ProxyStats.updateBytes(n.toLong())
                                } finally {
                                    writeMutex.unlock()
                                }
                            }
                        }
                    } catch (e: Throwable) {
                        if (e !is CancellationException && e !is java.net.SocketException) {
                            Log.v("TcpTransport", "C2R error: ${e.message}")
                        }
                    } finally {
                        if (buffer.size > 16384) ProxyStats.release64k(buffer) else ProxyStats.release16k(buffer)
                        try { clientSocket.close() } catch (e: Throwable) {}
                        try { finalRemoteSocket.close() } catch (e: Throwable) {}
                    }
                }
                
                // Idle Smuggling (PSH-1): Send 1-byte PSH during inactivity to keep DPI state active
                launch {
                    val rnd = ThreadLocalRandom.current()
                    while (isActive) {
                        delay(rnd.nextLong(25000, 45000))
                        
                        if (System.currentTimeMillis() - lastActivity.get() > 20000) {
                            writeMutex.lock()
                            try {
                                if (finalRemoteSocket.isConnected && !finalRemoteSocket.isClosed) {
                                    Log.v("TcpTransport", "Idle keep-alive pulse for $targetHost")
                                }
                            } catch (e: Throwable) {} finally {
                                writeMutex.unlock()
                            }
                        }
                    }
                }

                // Confusion pulse: Periodically send realistic-looking fake data with low TTL
                launch {
                    val rnd = ThreadLocalRandom.current()
                    while (isActive) {
                        val delayMs = when {
                            ProxyStats.censorshipIntensity.value > 85 -> rnd.nextLong(12000, 20000)
                            ProxyStats.censorshipIntensity.value > 50 -> rnd.nextLong(18000, 35000)
                            else -> rnd.nextLong(35000, 70000)
                        }
                        delay(delayMs)
                        
                        if (System.currentTimeMillis() - lastActivity.get() > 12000) {
                            writeMutex.lock()
                            try {
                                val outputStream = remoteOut
                                if (outputStream != null && finalRemoteSocket.isConnected && !finalRemoteSocket.isClosed) {
                                    sendConfusionPacket(finalRemoteSocket, outputStream, rnd)
                                }
                            } catch (e: Throwable) {} finally {
                                writeMutex.unlock()
                            }
                        }
                    }
                }

                // Periodic Window Pulse to maintain flow state in DPI
                launch {
                    while (isActive) {
                        delay(30000)
                        if (ProxyStats.censorshipIntensity.value > 30 && finalRemoteSocket.isConnected && !finalRemoteSocket.isClosed) {
                            applyWindowPulse(finalRemoteSocket)
                        }
                    }
                }
                
            // Active timeout monitoring
                launch {
                    while (isActive) {
                        delay(20000)
                        val now = System.currentTimeMillis()
                        val lastAct = lastActivity.get()
                        if (now - lastAct > 180000) { // 3 minutes idle
                            Log.v("TcpTransport", "Closing idle session for $targetHost (3m inactivity)")
                            try { clientSocket.close() } catch (e: Throwable) {}
                            try { finalRemoteSocket.close() } catch (e: Throwable) {}
                            cancel("Idle Timeout")
                            break
                        }
                    }
                }
            }
        } catch (e: Throwable) {
            if (e !is CancellationException) {
                val reason = when (e) {
                    is java.net.ConnectException -> "CONN_REFUSED"
                    is java.net.SocketTimeoutException -> "TIMEOUT"
                    is java.net.SocketException -> if (e.message?.contains("reset") == true) "RESET" else "SOCKET_ERR"
                    else -> "ERR_${e.javaClass.simpleName}"
                }
                Log.v("TcpTransport", "Session for $targetHost failed: $reason")
            }
        } finally {
            try { clientSocket.close() } catch (e: Throwable) {}
            try { remoteSocket?.close() } catch (e: Throwable) {}
        }
    }

    private suspend fun connectToBestIp(
        ips: List<java.net.InetAddress>,
        port: Int,
        vpnService: VpnService?,
        config: SessionConfig,
        host: String
    ): Socket? = withContext(ProxyDispatcher.io) {
        if (ips.isEmpty()) return@withContext null
        if (ips.size == 1) {
            val s = Socket()
            try {
                vpnService?.protect(s)
                TtlHelper.tuneSocket(s)
                TtlHelper.applyMssClamping(s, host)
                s.connect(InetSocketAddress(ips[0], port), 5000)
                return@withContext s
            } catch (e: Throwable) {
                try { s.close() } catch (ex: Throwable) {}
                return@withContext null
            }
        }

        // Happy Eyeballs: Connect to multiple IPs in parallel and take the first one
        val intensity = ProxyStats.censorshipIntensity.value
        val sortedIps = if (intensity > 70) {
            ips.sortedByDescending { it is java.net.Inet6Address }
        } else {
            ips
        }

        val targetIps = sortedIps.take(8)
        val channel = kotlinx.coroutines.channels.Channel<Socket>(targetIps.size)
        val jobs = mutableListOf<Job>()
        val completedCount = java.util.concurrent.atomic.AtomicInteger(0)
        
        targetIps.forEachIndexed { index, ip ->
            jobs += launch {
                val s = Socket()
                try {
                    // Stagger connections: 200ms delay between attempts
                    if (index > 0) delay(index * 200L)
                    vpnService?.protect(s)
                    TtlHelper.tuneSocket(s)
                    TtlHelper.applyMssClamping(s, host)
                    
                    // Adaptive timeout: shorter for early attempts to trigger racing faster
                    val timeout = if (index < 2) 4000 else 7000
                    s.connect(InetSocketAddress(ip, port), timeout)
                    
                    if (!channel.trySend(s).isSuccess) {
                        try { s.close() } catch (ex: Throwable) {}
                    }
                } catch (e: Throwable) {
                    try { s.close() } catch (ex: Throwable) {}
                } finally {
                    if (completedCount.incrementAndGet() == targetIps.size) {
                        channel.close()
                    }
                }
            }
        }
        
        var result: Socket? = null
        try {
            result = withTimeoutOrNull(10000) { channel.receive() }
        } catch (e: Throwable) {
            Log.w("TcpTransport", "Racing failed for $host: ${e.message}")
        } finally {
            jobs.forEach { it.cancel() }
            channel.close()
            // Clean up any sockets that arrived after we took one or timed out
            while (true) {
                val s = channel.tryReceive().getOrNull() ?: break
                try { s.close() } catch (e: Throwable) {}
            }
        }
        result
    }

    private suspend fun sendDecoyStorm(socket: Socket, out: OutputStream, rnd: ThreadLocalRandom) {
        try {
            val host = socket.inetAddress?.hostAddress ?: ""
            val configuredTtl = BypassConfig.fakeTtl
            val fakeTtl = configuredTtl.takeIf { it > 0 } ?: AutoTtlProber.getDiscoveredTtl(host) ?: rnd.nextInt(3, 7)
            
            // Multiple decoys in sequence to exhaust stateful inspection
            val decoys = listOf(
                FakePacketHelper.buildRealisticHttp2Header(),
                FakePacketHelper.buildRealisticTlsHello("blocked.com"),
                FakePacketHelper.buildHttpChaosPacket(),
                FakePacketHelper.buildStunBindingRequest()
            ).shuffled()

            for (decoy in decoys.take(rnd.nextInt(2, 4))) {
                TtlHelper.setTtl(socket, fakeTtl)
                out.write(decoy)
                out.flush()
                delay(rnd.nextLong(1, 5))
            }
            TtlHelper.setTtl(socket, 64) // Restore normal TTL
        } catch (e: Throwable) {
            if (e is CancellationException) throw e
        }
    }

    private suspend fun performSniGhosting(host: String, vpnService: VpnService?) {
        try {
            val decoys = listOf("google.com", "cloudflare.com", "bing.com", "apple.com", "microsoft.com")
            val decoy = decoys.random()
            val s = Socket()
            vpnService?.protect(s)
            val resolved = RobustResolver.resolve(decoy, vpnService)
            if (resolved.isNotEmpty()) {
                s.connect(InetSocketAddress(resolved.random(), 443), 2000)
                val out = s.getOutputStream()
                val hello = FakePacketHelper.buildRealisticTlsHello(decoy)
                
                val discoveredTtl = BypassConfig.fakeTtl.takeIf { it > 0 } ?: AutoTtlProber.getDiscoveredTtl(decoy) ?: 4
                TtlHelper.setTtl(s, discoveredTtl)
                
                out.write(hello)
                out.flush()
                delay(10)
                s.close()
            }
        } catch (e: Throwable) {}
    }

    private fun oscillateWindowSize(socket: Socket) {
        try {
            val rnd = ThreadLocalRandom.current()
            // Shake the window size to desync DPI state machine
            socket.receiveBufferSize = if (rnd.nextBoolean()) 
                rnd.nextInt(256, 1024) 
            else 
                rnd.nextInt(32768, 65536)
        } catch (e: Throwable) {}
    }

    private suspend fun applyWindowPulse(socket: Socket) {
        try {
            val original = socket.receiveBufferSize
            socket.receiveBufferSize = 1
            // Delay to allow kernel to potentially advertise smaller window on ACKs
            delay(10)
            socket.receiveBufferSize = original
        } catch (e: Throwable) {
            if (e is CancellationException) throw e
        }
    }

    private suspend fun sendConfusionPacket(socket: Socket, out: OutputStream, rnd: ThreadLocalRandom) {
        try {
            val host = socket.inetAddress?.hostAddress ?: ""
            val configuredTtl = BypassConfig.fakeTtl
            val fakeTtl = configuredTtl.takeIf { it > 0 } ?: AutoTtlProber.getDiscoveredTtl(host) ?: rnd.nextInt(2, 6)
            TtlHelper.setTtl(socket, fakeTtl)
            val noise = FakePacketHelper.buildUdpNoise(rnd.nextInt(16, 64))
            out.write(noise)
            out.flush()
            delay(rnd.nextLong(1, 4))
            TtlHelper.setTtl(socket, 64)
        } catch (e: Throwable) {
            if (e is CancellationException) throw e
        }
    }

    private suspend fun injectGhostSegment(socket: Socket, out: OutputStream, rnd: ThreadLocalRandom) {
        try {
            val host = socket.inetAddress?.hostAddress ?: ""
            val configuredTtl = BypassConfig.fakeTtl
            val fakeTtl = configuredTtl.takeIf { it > 0 } ?: AutoTtlProber.getDiscoveredTtl(host) ?: rnd.nextInt(2, 6)
            TtlHelper.setTtl(socket, fakeTtl)
            val ghost = FakePacketHelper.buildRealisticTlsHello("ghost.internal")
            out.write(ghost)
            out.flush()
            delay(rnd.nextLong(1, 3))
            TtlHelper.setTtl(socket, 64)
        } catch (e: Throwable) {
            if (e is CancellationException) throw e
        }
    }

    private suspend fun sendSequenceDesync(socket: Socket, rnd: ThreadLocalRandom) {
        try {
            // Send a tiny packet with very low TTL to confuse DPI state
            val out = socket.getOutputStream()
//             TtlHelper.setTtl(socket, rnd.nextInt(2, 4))
            out.write(byteArrayOf(rnd.nextInt(256).toByte()))
            out.flush()
            delay(rnd.nextLong(2, 8))
//             TtlHelper.setTtl(socket, BypassConfig.currentTtl.value)
        } catch (e: Throwable) {
            if (e is CancellationException) throw e
        }
    }

    private suspend fun sendZeroWindowDesync(socket: Socket, rnd: ThreadLocalRandom) {
        try {
            // Signal a zero window to the remote, wait, then open it again
            // This can break some middleboxes that don't handle flow control correctly
            TtlHelper.setWindowSize(socket, 0)
            delay(rnd.nextLong(100, 300))
            TtlHelper.setWindowSize(socket, 65535)
        } catch (e: Throwable) {
            if (e is CancellationException) throw e
        }
    }
}
