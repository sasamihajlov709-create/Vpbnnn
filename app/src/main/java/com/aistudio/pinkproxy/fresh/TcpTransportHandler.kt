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
import kotlinx.coroutines.selects.select

object TcpTransportHandler {

    @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
    suspend fun handleTcpSession(
        clientSocket: Socket,
        targetHost: String,
        targetPort: Int,
        vpnService: VpnService?,
        scope: CoroutineScope
    ) {
        var remoteSocket: Socket? = null
        var throughputJob: Job? = null
        try {
            val resolved = RobustResolver.resolve(targetHost, vpnService)
            if (resolved.isEmpty()) {
                Log.w("TcpTransport", "Resolution failed for $targetHost")
                clientSocket.close()
                return
            }
            ProxyStats.addTraffic(targetHost)
            val totalWrittenClient = java.util.concurrent.atomic.AtomicLong(0)

            val strategy = BypassConfig.getBestStrategyForHost(targetHost)
            val config = BypassConfig.getSessionConfig(targetHost, strategy, BypassConfig.currentRttMs.value)

            val start = System.currentTimeMillis()
            val censorship = BypassConfig.censorshipLevel.value
            
            var retryCount = 0
            val maxRetries = if (censorship > 80) 2 else 1
            
            while (retryCount <= maxRetries) {
                remoteSocket = try {
                    withTimeout(if (retryCount > 0) 8000 else 12000) {
                        val channel = kotlinx.coroutines.channels.Channel<Socket>(resolved.size)
                        val activeJobs = mutableListOf<Job>()
                        val attemptedSockets = java.util.concurrent.CopyOnWriteArrayList<Socket>()
                        // Aggressive racing: attempt more IPs if censorship is high or it is a retry
                        val attempted = if (censorship > 70 || retryCount > 0) resolved.size else minOf(resolved.size, 3)
                        val raceDelay = if (censorship > 70) 50L else 250L
                        val failures = java.util.concurrent.atomic.AtomicInteger(0)
                        val nextSignal = kotlinx.coroutines.channels.Channel<Unit>(1)
                        
                        for (i in 0 until attempted) {
                            val ip = resolved[i]
                            activeJobs += scope.launch(ProxyDispatcher.io) {
                                val s = Socket()
                                attemptedSockets.add(s)
                                try {
                                    try { vpnService?.protect(s) } catch (e: Throwable) {}
                                    TtlHelper.tuneSocket(s)
                                    val baseTimeout = (BypassConfig.currentRttMs.value * 3).coerceIn(1500, 7000)
                                    val jitter = ProxyStats.jitter.value
                                    val connectTimeout = (baseTimeout + jitter).toInt().coerceIn(2000, 10000)
                                    
                                    val startConnect = System.currentTimeMillis()
                                    try {
                                        s.connect(InetSocketAddress(ip, targetPort), connectTimeout)
                                        val rtt = System.currentTimeMillis() - startConnect
                                        ProxyStats.updateLatency(rtt)
                                        DnsCacheManager.recordIpSuccess(ip.hostAddress ?: "", rtt)
                                    } catch (e: Throwable) {
                                        nextSignal.trySend(Unit) // Start next racer immediately
                                        val elapsed = System.currentTimeMillis() - startConnect
                                        val msg = e.message?.lowercase() ?: ""
                                        DnsCacheManager.recordIpFailure(ip.hostAddress ?: "")
                                        
                                        val reason = when {
                                            elapsed >= connectTimeout - 500 -> BypassConfig.FailureReason.TIMEOUT
                                            msg.contains("reset") -> BypassConfig.FailureReason.TCP_RESET
                                            msg.contains("refused") -> BypassConfig.FailureReason.CONNECTION_REFUSED
                                            else -> BypassConfig.FailureReason.UNKNOWN
                                        }
                                        
                                        if (reason == BypassConfig.FailureReason.TIMEOUT) {
                                            BypassConfig.recordDpiFailure(strategy, targetHost, DpiType.CONNECTION_TIMEOUT)
                                            BypassConfig.recordFailure(strategy, targetHost, BypassConfig.FailureReason.TIMEOUT)
                                        } else if (reason == BypassConfig.FailureReason.TCP_RESET) {
                                            BypassConfig.recordDpiFailure(strategy, targetHost, DpiType.TCP_RESET)
                                            BypassConfig.recordFailure(strategy, targetHost, BypassConfig.FailureReason.TCP_RESET)
                                        }
                                        throw e
                                    }
                                    if (!channel.isClosedForSend) {
                                        channel.trySend(s)
                                    } else {
                                        s.close()
                                    }
                                } catch (e: Throwable) {
                                    try { s.close() } catch (ex: Exception) {}
                                    if (failures.incrementAndGet() == attempted) {
                                        channel.close()
                                    }
                                }
                            }
                            if (i < attempted - 1) {
                                val dynamicDelay = if (censorship > 85 || retryCount > 0) (raceDelay / 2) else (raceDelay + i * 100L)
                                withTimeoutOrNull(dynamicDelay) {
                                    nextSignal.receive()
                                }
                            }
                        }
                        var winnerSocket: Socket? = null
                        val winner = try {
                            val res = channel.receive()
                            winnerSocket = res
                            res
                        } catch (e: Throwable) {
                            throw Exception("All TCP connection attempts failed for $targetHost")
                        } finally {
                            channel.close()
                            activeJobs.forEach { it.cancel() }
                            attemptedSockets.forEach { s ->
                                if (s != winnerSocket) {
                                    try { s.close() } catch (e: Throwable) {}
                                }
                            }
                            while (true) {
                                val leftover = channel.tryReceive().getOrNull() ?: break
                                try { leftover.close() } catch (e: Throwable) {}
                            }
                        }
                        winner
                    }
                } catch (e: Throwable) {
                    if (retryCount < maxRetries && (e is java.net.SocketException || e is java.io.IOException || e is TimeoutCancellationException)) {
                        retryCount++
                        val dpiType = BypassConfig.identifyDpiType(e, targetHost, 0)
                        if (dpiType != DpiType.NONE) {
                            BypassConfig.recordDpiFailure(strategy, targetHost, dpiType)
                        } else {
                            val msg = e.message?.lowercase() ?: ""
                            val reason = when {
                                e is TimeoutCancellationException -> BypassConfig.FailureReason.TIMEOUT
                                msg.contains("reset") -> BypassConfig.FailureReason.TCP_RESET
                                msg.contains("refused") -> BypassConfig.FailureReason.CONNECTION_REFUSED
                                else -> BypassConfig.FailureReason.UNKNOWN
                            }
                            BypassConfig.recordFailure(strategy, targetHost, reason)
                        }
                        ProxyStats.recordGlobalFailure()
                        delay(500)
                        continue
                    }
                    Log.w("TcpTransport", "Connection failed to $targetHost: ${e.message}")
                    ProxyStats.recordGlobalFailure()
                    clientSocket.close()
                    return
                }
                break // Success, exit retry loop
            }
            
            if (remoteSocket == null) {
                clientSocket.close()
                return
            }

            // Optimization: Reset timeouts and enable TCP_NODELAY for both ends of the tunnel
            try {
                clientSocket.soTimeout = 0
                remoteSocket.soTimeout = 0
                remoteSocket.tcpNoDelay = true
                
                // TCP Fast Open (TFO) support for API 30+
                if (android.os.Build.VERSION.SDK_INT >= 30) {
                    try {
                        // Use reflection or the constant if available. 
                        // StandardSocketOptions.TCP_FAST_OPEN might not be visible in all environments.
                        @Suppress("UNCHECKED_CAST")
                        val tfo = java.net.StandardSocketOptions::class.java.getField("TCP_FAST_OPEN").get(null) as? java.net.SocketOption<Int>
                        if (tfo != null) remoteSocket.setOption(tfo, 1)
                    } catch (e: Throwable) {}
                }

                val intensity = ProxyStats.censorshipIntensity.value
                val isWindowMangle = strategy == BypassStrategy.WINDOW_SIZE_MANGLE || strategy == BypassStrategy.TCP_ZERO_WINDOW_STALL
                
                // Adaptive buffer sizes: small for DPI evasion, large for throughput
                val bufSize = when {
                    isWindowMangle -> 1460
                    intensity > 90 -> 8192
                    intensity > 75 -> 16384
                    intensity > 50 -> 32768
                    else -> 128 * 1024
                }
                
                remoteSocket.sendBufferSize = if (isWindowMangle) 1460 else 128 * 1024
                remoteSocket.receiveBufferSize = bufSize
                clientSocket.sendBufferSize = bufSize
                clientSocket.receiveBufferSize = 128 * 1024
                
            } catch (e: Throwable) {}

            val connectTime = System.currentTimeMillis() - start
            BypassConfig.TrafficShaper.updateRtt(connectTime)

            val clientIn = clientSocket.getInputStream()
            val clientOut = clientSocket.getOutputStream()
            val remoteIn = remoteSocket.getInputStream()
            val remoteOut = remoteSocket.getOutputStream()
            
            // Start Throughput Monitor to detect stalled connections or blackholes
            var lastTotalForStall = totalWrittenClient.get()
            var silentPeriods = 0
            throughputJob = scope.launch(ProxyDispatcher.io) {
                while (isActive && remoteSocket.isConnected && !remoteSocket.isClosed) {
                    delay(10000) // Check every 10s
                    val total = totalWrittenClient.get()
                    val delta = total - lastTotalForStall
                    
                    if (delta < 32) { // Less than 32 bytes in 10s is very suspicious
                        silentPeriods++
                        if (silentPeriods >= 3) { // 30s of silence
                             BypassConfig.recordFailure(strategy, targetHost)
                             if (BypassConfig.isHostCensored(targetHost)) {
                                 ProxyStats.recordDpiEvent(DpiType.CONNECTION_TIMEOUT)
                             }
                             // Proactive disconnect if it's a known blocked host
                             if (BypassConfig.isHostCensored(targetHost)) {
                                 try { remoteSocket.close(); clientSocket.close() } catch (e: Throwable) {}
                                 break
                             }
                        }
                    } else {
                        silentPeriods = 0
                    }
                    lastTotalForStall = total
                }
            }

            val lastActivity = AtomicLong(System.currentTimeMillis())

            coroutineScope {
                val inactivityJob = launch {
                    while (isActive) {
                        delay(30000)
                        val now = System.currentTimeMillis()
                        val idleTime = now - lastActivity.get()
                        // Adaptive idle timeout: tighter when system is under load or high censorship
                        val maxIdle = when {
                            ProxyStats.activeConnections.value > 50 -> 60000L
                            ProxyStats.censorshipIntensity.value > 80 -> 120000L
                            else -> 300000L // 5 minutes
                        }
                        if (idleTime > maxIdle) {
                            Log.v("TcpTransport", "Reaping idle session: $targetHost (idle ${idleTime/1000}s)")
                            this@coroutineScope.cancel("Idle timeout")
                            break
                        }
                    }
                }

                // Keep-alive to prevent NAT/Firewall timeout with standard SO_KEEPALIVE
                val keepAliveJob = launch {
                    val rnd = ThreadLocalRandom.current()
                    while (isActive) {
                        delay(rnd.nextLong(45000, 90000))
                        if (System.currentTimeMillis() - lastActivity.get() > 60000) {
                            try { 
                                remoteSocket?.keepAlive = true
                                 
                            } catch (e: Throwable) {}
                        }
                    }
                }

                // Forward from Remote to Client (Direct)
                val remoteToClient = launch(ProxyDispatcher.io) {
                    val intensity = ProxyStats.censorshipIntensity.value
                    val activeConns = ProxyStats.activeConnections.value
                    val speed = ProxyStats.speedBytesPerSecond.value
                    val stability = ProxyStats.stabilityScore.value
                    val rnd = ThreadLocalRandom.current()
                    
                    // Adaptive buffer size: more conservative when under censorship or high load
                    val buffer = when {
                        intensity > 90 || activeConns > 100 -> ProxyStats.obtain8k()
                        intensity > 70 || activeConns > 50 || stability < 60 -> ProxyStats.obtain16k()
                        speed > 1024 * 1024 -> ProxyStats.obtain64k()
                        else -> ProxyStats.obtain16k()
                    }
                    val bufSize = buffer.size
                    
                    var firstResponse = true
                    var totalRead = 0L
                    var consecutiveTimeouts = 0
                    try {
                        var n: Int
                        while (isActive) {
                            try {
                                remoteSocket?.soTimeout = if (totalRead == 0L) 15000 else 60000
                                n = remoteIn.read(buffer)
                                consecutiveTimeouts = 0
                            } catch (e: Throwable) {
                                if (e is java.io.InterruptedIOException || e is java.net.SocketTimeoutException) {
                                    consecutiveTimeouts++
                                    val maxTimeouts = if (totalRead == 0L) 2 else 5
                                    if (consecutiveTimeouts >= maxTimeouts || !isActive) {
                                        if (totalRead == 0L) {
                                            BypassConfig.recordFailure(strategy, targetHost)
                                        }
                                        break
                                    }
                                    continue
                                }
                                throw e
                            }
                            if (n == -1) break
                            if (n > 0) {
                                totalRead += n
                                if (firstResponse) {
                                    firstResponse = false
                                    val rtt = System.currentTimeMillis() - start
                                    BypassConfig.recordSuccess(strategy, rtt, targetHost)
                                    
                                    // Deep Packet Inspection evasion: block marker detection
                                    if (n >= 7) {
                                        val contentType = buffer[0].toInt() and 0xFF
                                        if (contentType == 0x15) { // TLS Alert
                                            val alertLevel = buffer[5].toInt() and 0xFF
                                            val alertDesc = buffer[6].toInt() and 0xFF
                                            ProxyStats.logRecovery("DPI Alert Detected: TLS $alertLevel/$alertDesc on $targetHost")
                                            BypassConfig.recordDpiFailure(strategy, targetHost, DpiType.TLS_SNI_BLOCK)
                                            throw java.io.IOException("TLS Alert (DPI Block)")
                                        } else if (contentType == 0x16 || contentType == 0x17) {
                                            // Valid TLS Handshake or App Data
                                        } else {
                                            // Possible HTTP or other
                                            val scanLen = n.coerceAtMost(1024)
                                            val lowStr = String(buffer, 0, scanLen, Charsets.US_ASCII).lowercase()
                                            if (lowStr.contains("forbidden") || lowStr.contains("access denied") || lowStr.contains("blocked") || lowStr.contains("content filter")) {
                                                ProxyStats.logRecovery("DPI Block Page Detected on $targetHost")
                                                BypassConfig.recordDpiFailure(strategy, targetHost, DpiType.HTTP_BLOCK)
                                                throw java.io.IOException("HTTP DPI Block")
                                            }
                                        }
                                    }
                                }
                                
                                lastActivity.set(System.currentTimeMillis())
                                clientOut.write(buffer, 0, n)
                                clientOut.flush()
                                ProxyStats.updateBytes(n.toLong())
                                
                                // Smart Throttling & Traffic Pattern Obfuscation
                                if (intensity > 40) {
                                    // Random micro-delays to break timing analysis (Side-channel protection)
                                    if (rnd.nextInt(100) < (intensity - 20)) {
                                        val d = rnd.nextLong(1, (intensity / 15).toLong().coerceAtLeast(2))
                                        delay(d)
                                    }
                                    
                                    // Adaptive Shaping based on congestion and stability
                                    val cwnd = ProxyStats.congestionWindow.value
                                    if (cwnd < 30 || stability < 80) {
                                        val throttleDelay = (1500L / (cwnd.coerceAtLeast(1) + (stability / 4))).coerceAtMost(50)
                                        if (throttleDelay > 1) delay(throttleDelay)
                                    }
                                } else {
                                    if (totalRead % (256 * 1024) == 0L) yield()
                                }
                            }
                        }
                    } catch (e: Throwable) {
                        if (e is CancellationException) throw e
                        val msg = e.message?.lowercase() ?: ""
                        val isEarly = totalRead < 32768L || (System.currentTimeMillis() - start < 15000)
                        
                        if (totalRead == 0L && System.currentTimeMillis() - start < 20000) {
                            BypassConfig.recordFailure(strategy, targetHost)
                            if (msg.contains("reset") || msg.contains("pipe")) ProxyStats.recordMssFailure()
                        }
                        
                        if (isEarly && msg.contains("reset")) {
                             val dpiType = DpiType.TCP_RESET
                             ProxyStats.recordDpiEvent(dpiType)
                             BypassConfig.recordDpiFailure(strategy, targetHost, dpiType)
                             ProxyStats.logRecovery("Connection Reset by Peer/DPI: $targetHost")
                        } else if (isEarly && msg.contains("timeout")) {
                             val dpiType = DpiType.CONNECTION_TIMEOUT
                             ProxyStats.recordDpiEvent(dpiType)
                             BypassConfig.recordDpiFailure(strategy, targetHost, dpiType)
                        } else if (isEarly) {
                             ProxyStats.recordCensorshipEvent(true)
                             BypassConfig.recordFailure(strategy, targetHost, BypassConfig.FailureReason.UNKNOWN)
                        }
                    } finally {
                        when (bufSize) {
                            8192 -> ProxyStats.release8k(buffer)
                            16384 -> ProxyStats.release16k(buffer)
                            65536 -> ProxyStats.release64k(buffer)
                            else -> {}
                        }
                        try { clientSocket.shutdownOutput() } catch (e: Throwable) {}
                    }
                }

                // Forward from Client to Remote (with Bypass)
                val clientToRemote = launch(ProxyDispatcher.io) {
                    val buffer = ProxyStats.obtain64k()
                    val rnd = ThreadLocalRandom.current()
                    var detectedSni: String? = null
                    val isMssClamp = strategy == BypassStrategy.TCP_MSS_CLAMP
                    
                    try {
                        var n: Int
                        var packetsCount = 0
                        var clientTimeouts = 0
                        while (isActive) {
                            try {
                                clientSocket.soTimeout = 60000
                                n = clientIn.read(buffer)
                                clientTimeouts = 0
                            } catch (e: Throwable) {
                                if (e is java.io.InterruptedIOException || e is java.net.SocketTimeoutException) {
                                    clientTimeouts++
                                    if (clientTimeouts >= 5 || !isActive) break
                                    continue
                                }
                                throw e
                            }
                            if (n == -1) break
                            if (n > 0) {
                                lastActivity.set(System.currentTimeMillis())
                                val currentIntensity = ProxyStats.censorshipIntensity.value
                                packetsCount++
                                
                                if (packetsCount == 1) {
                                    val sniOffset = TlsParser.findSniOffset(buffer, n)
                                    if (sniOffset != -1) {
                                        val realSni = TlsParser.extractHostname(buffer, n, sniOffset)
                                        if (realSni != null) {
                                            if (BypassConfig.isHostCensored(realSni)) {
                                                // High censorship host! Use EXTREME strategies for maximum effectiveness
                                                val forceStrategy = if (currentIntensity > 80) BypassStrategy.ZAPRET_EXTREME else BypassStrategy.BYEBYEDPI_EXTREME
                                                ProxyStats.logRecovery("Censorship Detected: Auto-Upgrading to ${forceStrategy.name} for $realSni")
                                                val forceConfig = BypassConfig.getSessionConfig(realSni, forceStrategy, BypassConfig.currentRttMs.value)
                                                BypassConfig.applyBypass(remoteSocket!!, remoteOut, buffer, n, forceConfig, realSni)
                                                packetsCount++
                                                totalWrittenClient.addAndGet(n.toLong())
                                                ProxyStats.updateBytes(n.toLong())
                                                continue
                                            } else if (realSni != targetHost) {
                                                ProxyStats.logRecovery("Deep Packet Analysis: Found real SNI -> $realSni")
                                                // Real hostname found! Get specific strategy for it
                                                val realStrategy = BypassConfig.getBestStrategyForHost(realSni)
                                                if (realStrategy != strategy) {
                                                     ProxyStats.logRecovery("Strategy Upgrade: Switching to ${realStrategy.name} for $realSni")
                                                     val realConfig = BypassConfig.getSessionConfig(realSni, realStrategy, BypassConfig.currentRttMs.value)
                                                     BypassConfig.applyBypass(remoteSocket!!, remoteOut, buffer, n, realConfig, realSni)
                                                     packetsCount++
                                                     totalWrittenClient.addAndGet(n.toLong())
                                                     ProxyStats.updateBytes(n.toLong())
                                                     continue
                                                }
                                            }
                                        }
                                    }
                                }

                                val stability = ProxyStats.stabilityScore.value
                                if (packetsCount <= 3 || (currentIntensity > 85 && packetsCount <= 12) || (stability < 50 && packetsCount <= 20)) {
                                    // Apply full bypass to initial handshake/header packets
                                    val activeHost = detectedSni ?: targetHost
                                    try {
                                        BypassConfig.applyBypass(remoteSocket!!, remoteOut, buffer, n, config, activeHost)
                                    } catch (e: Throwable) {
                                        if (e is CancellationException) throw e
                                        BypassConfig.recordFailure(strategy, activeHost)
                                        throw e
                                    }
                                } else {
                                    // Advanced Fragmentation & MSS Clamping simulation
                                    if ((isMssClamp || currentIntensity > 50) && n > 1100) {
                                        var offset = 0
                                        val mss = when {
                                            isMssClamp -> 512 + rnd.nextInt(300)
                                            currentIntensity > 90 -> 256 + rnd.nextInt(512)
                                            else -> 1100 + rnd.nextInt(200)
                                        }
                                        while (offset < n) {
                                            val sz = minOf(mss, n - offset)
                                            remoteOut.write(buffer, offset, sz)
                                            remoteOut.flush()
                                            offset += sz
                                            if (offset < n) {
                                                val d = if (currentIntensity > 80) rnd.nextLong(2, 10) else 1L
                                                delay(d)
                                            }
                                        }
                                    } else if (currentIntensity > 55 && n > 5) {
                                        // Opportunistic fragmentation with smarter jitter
                                        if (rnd.nextInt(100) < (currentIntensity - 30).coerceAtLeast(10)) {
                                            val split = rnd.nextInt(1, n)
                                            remoteOut.write(buffer, 0, split)
                                            remoteOut.flush()
                                            
                                            if (currentIntensity > 75) delay(rnd.nextLong(1, 8))
                                            
                                            // Confuse DPI state tracking with OOB data injection
                                            if (currentIntensity > 85 && rnd.nextInt(100) < 35) {
                                                try { remoteSocket?.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                                            }

                                            remoteOut.write(buffer, split, n - split)
                                            remoteOut.flush()
                                            
                                            // Occasionally send an urgent byte to confuse DPI state tracking
                                            if (currentIntensity > 70 && rnd.nextInt(100) < 20) {
                                                try { remoteSocket?.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                                            }
                                        } else {
                                            remoteOut.write(buffer, 0, n)
                                            remoteOut.flush()
                                        }
                                    } else {
                                        remoteOut.write(buffer, 0, n)
                                        if (strategy == BypassStrategy.TCP_RANDOM_PADDING && rnd.nextInt(100) < 40) {
                                            try { remoteSocket?.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                                        }
                                        remoteOut.flush()
                                    }
                                }
                                totalWrittenClient.addAndGet(n.toLong())
                                ProxyStats.updateBytes(n.toLong())
                            }
                        }
                    } catch (e: Throwable) {
                        if (e !is CancellationException) {
                            BypassConfig.TrafficShaper.recordError()
                            if (System.currentTimeMillis() - start < 15000) {
                                BypassConfig.recordFailure(strategy, targetHost)
                            }
                        }
                    } finally {
                        ProxyStats.release64k(buffer)
                        try { remoteSocket?.shutdownOutput() } catch (e: Throwable) {}
                    }
                }

                select<Unit> {
                    remoteToClient.onJoin {}
                    clientToRemote.onJoin {}
                }
                
                // Allow up to 2 seconds for graceful termination of the other direction
                withTimeoutOrNull(2000) {
                    if (remoteToClient.isActive) remoteToClient.join()
                    if (clientToRemote.isActive) clientToRemote.join()
                }
                
                try { clientSocket.close() } catch(e: Throwable) {}
                try { remoteSocket?.close() } catch(e: Throwable) {}
                
                inactivityJob.cancel()
                keepAliveJob.cancel()
                remoteToClient.cancel()
                clientToRemote.cancel()
            }
        } catch (e: Throwable) {
            Log.v("TcpTransport", "Session $targetHost:$targetPort failed: ${e.message}")
        } finally {
            try { clientSocket.close() } catch (e: Throwable) {}
            try { remoteSocket?.close() } catch (e: Throwable) {}
            throughputJob?.cancel()
        }
    }
}
