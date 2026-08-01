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
            val isTls = targetPort == 443 || targetPort == 8443

            val start = System.currentTimeMillis()
            val censorship = BypassConfig.censorshipLevel.value
            
            var retryCount = 0
            val maxRetries = if (censorship > 80) 2 else 1
            
            val isHostBlocked = BypassConfig.isHostProbablyCensored(targetHost)
            var shouldRaceImmediately = censorship > 45 || isHostBlocked || HostClassifier.classify(targetHost) != HostCategory.OTHER

            var strategy = BypassConfig.getBestStrategyForHost(targetHost)
            
            // Check for ECH presence and adjust strategy
            val dnsRecords = RobustResolver.getCachedDetailed(targetHost)
            val hasEch = dnsRecords?.any { it.type == 65 && it.address.hostAddress == "0.0.0.1" } ?: false
            if (hasEch && censorship > 30) {
                strategy = BypassStrategy.ECH_FRAG
                Log.d("TcpTransport", "ECH detected for $targetHost, applying ECH_FRAG")
            }

            var config = BypassConfig.getSessionConfig(targetHost, strategy, BypassConfig.currentRttMs.value)

            // Dynamic adjustment of maxRetries based on real-time success rate
            val successRate = ProxyStats.getSuccessRate()
            val adjustedMaxRetries = when {
                successRate < 30 -> 3
                successRate < 60 -> 2
                else -> maxRetries
            }

            // Proactively probe for TTL for this host in the background
            AutoTtlProber.scheduleProbe(targetHost, targetPort, vpnService, scope)
            
            // SNI Ghosting: send a fake handshake to a whitelisted domain with low TTL
            // to "prime" the DPI state machine with an innocent session before the real one.
            if (censorship > 65 && isTls && retryCount == 0) {
                scope.launch(ProxyDispatcher.io) {
                    performSniGhosting(targetHost, vpnService)
                }
            }
            
            // Use discovered MTU if available
            val discoveredMtu = AutoTtlProber.getDiscoveredMtu(targetHost)
            if (discoveredMtu < 1300) {
                Log.d("TcpTransport", "Using optimized MTU $discoveredMtu for $targetHost")
            }

            while (retryCount <= adjustedMaxRetries) {
                if (retryCount > 0 || shouldRaceImmediately) {
                    // Strategy Racing: try top strategies in parallel
                    val racers = mutableListOf<BypassStrategy>()
                    if (shouldRaceImmediately && retryCount == 0) {
                        racers.add(strategy)
                        racers.add(DpiEngine.getBestStrategy(HostClassifier.classify(targetHost)))
                        racers.add(BypassStrategy.SNI_SPLIT)
                    } else {
                        // On retries, broaden the search
                        racers.add(DpiEngine.getBestStrategy(HostClassifier.classify(targetHost)))
                        racers.add(BypassStrategy.TCP_OOB_DESYNC)
                        racers.add(BypassStrategy.BYEBYEDPI_HYBRID)
                        racers.add(BypassStrategy.TLS_SNI_SKEW)
                        racers.add(BypassStrategy.TCP_RETRANS_FAKE)
                    }
                    val finalRacers = racers.distinct().take(if (BypassConfig.isPanicMode) 5 else 3)
                    
                    remoteSocket = try {
                        withTimeout(if (retryCount == 0) 8000 else 15000) {
                            val winnerChannel = kotlinx.coroutines.channels.Channel<Pair<Socket, BypassStrategy>>(finalRacers.size)
                            val jobs = finalRacers.map { strat ->
                                scope.launch(ProxyDispatcher.io) {
                                    try {
                                        val racerConfig = BypassConfig.getSessionConfig(targetHost, strat, BypassConfig.currentRttMs.value)
                                        val s = connectToBestIp(resolved, targetPort, vpnService, racerConfig, targetHost)
                                        if (s != null) {
                                            winnerChannel.trySend(s to strat)
                                        }
                                    } catch (e: Throwable) {}
                                }
                            }
                            val winner = try {
                                winnerChannel.receive()
                            } finally {
                                jobs.forEach { it.cancel() }
                                winnerChannel.close()
                            }
                            strategy = winner.second
                            config = BypassConfig.getSessionConfig(targetHost, strategy, BypassConfig.currentRttMs.value)
                            winner.first
                        }
                    } catch (e: Throwable) {
                        null
                    }
                } else {
                    // Fast Failover: Connect with best strategy, but start racing if it takes too long
                    remoteSocket = try {
                         val deferred = scope.async(ProxyDispatcher.io) {
                             connectToBestIp(resolved, targetPort, vpnService, config, targetHost)
                         }
                         withTimeoutOrNull(1200) {
                             deferred.await()
                         }
                    } catch (e: Throwable) { null }
                    
                    if (remoteSocket == null) {
                        shouldRaceImmediately = true // Trigger racing on next loop or immediately
                        continue 
                    }
                }

                if (remoteSocket != null) break
                
                retryCount++
                if (retryCount <= maxRetries) {
                    ProxyStats.recordGlobalFailure()
                    
                    // Strategy Chaining: Try fallback if available
                    val fallback = DpiEngine.getFallbackStrategy(strategy)
                    if (fallback != null) {
                        strategy = fallback
                        config = BypassConfig.getSessionConfig(targetHost, strategy, BypassConfig.currentRttMs.value)
                        ProxyStats.logRecovery("Auto-Autopilot: Falling back to ${strategy.name} for $targetHost")
                    } else {
                        // If no specific fallback, rotate to something better
                        strategy = DpiEngine.getBestStrategy(HostClassifier.classify(targetHost), targetHost)
                        config = BypassConfig.getSessionConfig(targetHost, strategy, BypassConfig.currentRttMs.value)
                    }

                    // Proactively re-probe host on failure to adapt to routing changes
                    AutoTtlProber.scheduleProbe(targetHost, targetPort, vpnService, scope)
                    delay(200L * retryCount)
                }
            }

            val finalSocket = remoteSocket ?: throw Exception("Failed to connect to $targetHost after retries")
            remoteSocket = finalSocket
            
            // Optimization: Reset timeouts and enable TCP_NODELAY for both ends of the tunnel
            try {
                clientSocket.soTimeout = 0
                remoteSocket.soTimeout = 0
                remoteSocket.tcpNoDelay = true
                
                // Tune MSS based on discovered MTU
                val mss = (AutoTtlProber.getDiscoveredMtu(targetHost) - 40).coerceAtLeast(512)
                TtlHelper.setMss(remoteSocket, mss)
                
                val intensity = ProxyStats.censorshipIntensity.value
                val rnd = java.util.concurrent.ThreadLocalRandom.current()

                // Adaptive Window Size Modulation
                if (intensity > 60) {
                    remoteSocket.receiveBufferSize = rnd.nextInt(8192, 32768)
                    remoteSocket.sendBufferSize = rnd.nextInt(8192, 32768)
                }

                // TCP Fast Open (TFO) support for API 30+
                if (android.os.Build.VERSION.SDK_INT >= 30) {
                    try {
                        val socketOptions = Class.forName("java.net.StandardSocketOptions")
                        val tfoField = socketOptions.getField("TCP_FAST_OPEN")
                        @Suppress("UNCHECKED_CAST")
                        val tfo = tfoField.get(null) as? java.net.SocketOption<Int>
                        if (tfo != null) remoteSocket.setOption(tfo, 1)
                    } catch (e: Throwable) {
                        try {
                            // Fallback to internal constants if StandardSocketOptions reflection fails
                            remoteSocket.setOption(java.net.StandardSocketOptions.SO_KEEPALIVE, true)
                        } catch (ex: Throwable) {}
                    }
                }

                val isWindowMangle = strategy == BypassStrategy.WINDOW_SIZE_MANGLE || 
                                   strategy == BypassStrategy.TCP_ZERO_WINDOW_STALL || 
                                   strategy == BypassStrategy.TCP_WINDOW_SHRINK ||
                                   strategy == BypassStrategy.TCP_WINDOW_SIZE_JITTER
                
                // Adaptive buffer sizes: small for DPI evasion, large for throughput
                val bufSize = when {
                    isWindowMangle -> 1024
                    intensity > 90 -> 4096
                    intensity > 75 -> 8192
                    intensity > 50 -> 16384
                    else -> 128 * 1024
                }
                
                if (strategy == BypassStrategy.TCP_ZERO_WINDOW_STALL) {
                    TtlHelper.setWindowSize(remoteSocket, 0)
                    scope.launch {
                        delay(rnd.nextLong(300, 800))
                        TtlHelper.setWindowSize(remoteSocket, bufSize)
                    }
                } else if (strategy == BypassStrategy.TCP_WINDOW_SHRINK) {
                    TtlHelper.setWindowSize(remoteSocket, rnd.nextInt(16, 64))
                } else if (strategy == BypassStrategy.TCP_WINDOW_SIZE_JITTER) {
                    scope.launch {
                        while (isActive && remoteSocket.isConnected) {
                            TtlHelper.setWindowSize(remoteSocket, rnd.nextInt(64, 1460))
                            delay(rnd.nextLong(2000, 5000))
                        }
                    }
                } else if (isWindowMangle) {
                    TtlHelper.setWindowSize(remoteSocket, rnd.nextInt(256, 1460))
                }
                
                remoteSocket.sendBufferSize = if (isWindowMangle) 1460 else 128 * 1024
                remoteSocket.receiveBufferSize = bufSize
                clientSocket.sendBufferSize = bufSize
                clientSocket.receiveBufferSize = 128 * 1024
                
            } catch (e: Throwable) {}

            val connectTime = System.currentTimeMillis() - start
            BypassConfig.TrafficShaper.updateRtt(connectTime)
            DpiEngine.recordRtt(targetHost, connectTime)

            val clientIn = clientSocket.getInputStream()
            val clientOut = clientSocket.getOutputStream()
            val remoteIn = remoteSocket.getInputStream()
            val remoteOut = remoteSocket.getOutputStream()
            
            // Start Throughput Monitor to detect stalled connections or blackholes
            var lastTotalForStall = totalWrittenClient.get()
            var silentPeriods = 0
            val jobIsTls = isTls
            throughputJob = scope.launch(ProxyDispatcher.io) {
                while (isActive && remoteSocket.isConnected && !remoteSocket.isClosed) {
                    val activeConnections = ProxyStats.activeConnections.value
                    val checkInterval = if (activeConnections > 50) 5000L else 10000L
                    delay(checkInterval) 
                    
                    val total = totalWrittenClient.get()
                    val delta = total - lastTotalForStall
                    
                    if (delta < 32) { 
                        silentPeriods++
                        
                        // "Kick" the connection if it's stalled
                        if (silentPeriods >= 2) {
                            try {
                                val rnd = ThreadLocalRandom.current()
                                // Send OOB byte to trigger response or wake up state
                                remoteSocket.sendUrgentData(rnd.nextInt(256))
                                val intensity = ProxyStats.censorshipIntensity.value
                                
                                if (intensity > 80) {
                                     // Adaptive "Kick": send different types of noise
                                     when(rnd.nextInt(3)) {
                                         0 -> remoteOut.write(FakePacketHelper.buildFakeTcpKeepAlive())
                                         1 -> remoteOut.write(FakePacketHelper.buildTlsHeartbeat())
                                         2 -> remoteOut.write(FakePacketHelper.buildUdpNoise(rnd.nextInt(5, 15)))
                                     }
                                     remoteOut.flush()
                                }
                                Log.v("TcpTransport", "Proactive kick sent to $targetHost (Stall detected)")
                            } catch (e: Throwable) {}
                        }

                        if (silentPeriods >= (if (ProxyStats.censorshipIntensity.value > 85) 3 else 4)) { 
                             BypassConfig.recordFailure(strategy, targetHost)
                             if (BypassConfig.isHostCensored(targetHost)) {
                                 ProxyStats.recordDpiEvent(if (jobIsTls) DpiType.SSL_STALL else DpiType.TCP_STALL)
                                 // Force higher intensity on stall
                                 ProxyStats.updateCensorshipIntensity((ProxyStats.censorshipIntensity.value + 10).coerceAtMost(100))
                             }
                             // Proactive disconnect
                             try { remoteSocket.close(); clientSocket.close() } catch (e: Throwable) {}
                             break
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

                // Confusion pulse for DPI evasion
                startConfusionPulse(targetHost, remoteOut, remoteSocket!!, this)

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
                    val startTime = System.currentTimeMillis()
                    
                    try {
                        var n: Int
                        while (isActive) {
                            try {
                                val intensity = ProxyStats.censorshipIntensity.value
                                if (intensity > 50) {
                                    applyWindowChaos(remoteSocket, intensity, rnd)
                                    applyWindowPulse(intensity, rnd)
                                }
                                remoteSocket?.soTimeout = if (totalRead == 0L) 15000 else 60000
                                n = remoteIn.read(buffer)
                                consecutiveTimeouts = 0
                            } catch (e: Throwable) {
                                if (e is java.io.InterruptedIOException || e is java.net.SocketTimeoutException) {
                                    consecutiveTimeouts++
                                    
                                    // Blackhole detection: If we sent data but got NOTHING back for a while
                                    val sent = totalWrittenClient.get().toInt()
                                    if (totalRead == 0L && sent > 0) {
                                        val duration = System.currentTimeMillis() - startTime
                                        if (BypassConfig.detectBlackhole(targetHost, sent, 0, duration)) {
                                            break // Exit loop, blackhole confirmed
                                        }
                                    }
                                    
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
                                    DpiEngine.recordRtt(targetHost, rtt)
                                    
                                    // Deep Packet Inspection evasion: block marker detection
                                    if (n >= 7) {
                                        val contentType = buffer[0].toInt() and 0xFF
                                        if (contentType == 0x15) { // TLS Alert
                                            val alertLevel = buffer[5].toInt() and 0xFF
                                            val alertDesc = buffer[6].toInt() and 0xFF
                                            ProxyStats.logRecovery("DPI Alert Detected: TLS $alertLevel/$alertDesc on $targetHost")
                                            
                                            val dpiType = when (alertDesc) {
                                                112 -> DpiType.TLS_SNI_BLOCK // unrecognized_name
                                                80 -> DpiType.TLS_SNI_BLOCK  // internal_error (sometimes used for blocks)
                                                40 -> DpiType.TLS_SNI_BLOCK  // handshake_failure
                                                else -> DpiType.TLS_SNI_BLOCK
                                            }
                                            BypassConfig.recordDpiFailure(strategy, targetHost, dpiType)
                                            throw java.io.IOException("TLS Alert (DPI Block: $alertDesc)")
                                        } else if (contentType == 0x16 || contentType == 0x17) {
                                            // Valid TLS Handshake or App Data
                                        } else {
                                            // Possible HTTP or other
                                            val scanLen = n.coerceAtMost(2048)
                                            val lowStr = String(buffer, 0, scanLen, Charsets.US_ASCII).lowercase()
                                            val isBlocked = lowStr.contains("forbidden") || 
                                                           lowStr.contains("access denied") || 
                                                           lowStr.contains("blocked") || 
                                                           lowStr.contains("content filter") ||
                                                           lowStr.contains("connection refused") ||
                                                           lowStr.contains("error_code") ||
                                                           lowStr.contains("cloud-flare") && lowStr.contains("blocked") ||
                                                           lowStr.contains("nginx") && lowStr.contains("403") ||
                                                           lowStr.contains("fortinet") ||
                                                           lowStr.contains("sophos") ||
                                                           lowStr.contains("sonicwall")

                                            if (isBlocked) {
                                                ProxyStats.logRecovery("DPI/Firewall Block Detected on $targetHost (Keywords found)")
                                                BypassConfig.recordDpiFailure(strategy, targetHost, DpiType.HTTP_BLOCK)
                                                throw java.io.IOException("DPI Block Identified")
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
                                    // Using Gaussian distribution for more natural jitter
                                    if (rnd.nextInt(100) < (intensity - 20)) {
                                        val mean = (intensity / 15.0).coerceAtLeast(1.5)
                                        val stdDev = mean / 3.0
                                        val d = (rnd.nextGaussian() * stdDev + mean).toLong().coerceIn(1, 15)
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
                             BypassConfig.recordFailure(strategy, targetHost, FailureReason.UNKNOWN)
                        }
                    } finally {
                        ProxyStats.releasePool(buffer)
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
                                val currentIntensity = ProxyStats.censorshipIntensity.value
                                if (currentIntensity > 60) {
                                    applyWindowPulse(currentIntensity, rnd)
                                }
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
                                        while (offset < n) {
                                            // Dynamic MSS from config (automated by DpiEngine/BypassConfig)
                                            val mss = if (isMssClamp) minOf(config.mss, 512 + rnd.nextInt(300)) else config.mss
                                            val sz = minOf(mss, n - offset)
                                            remoteOut.write(buffer, offset, sz)
                                            remoteOut.flush()
                                            
                                            // Periodically oscillate window size to confuse DPI reassembly engine
                                            oscillateWindowSize(remoteSocket!!, currentIntensity)
                                            
                                            offset += sz

                                            // TCP Retransmission Simulation (Segment Overlap with junk)
                                            if (currentIntensity > 85 && rnd.nextInt(100) < 40) {
                                                val junk = FakePacketHelper.buildFakeRetransmission(buffer.copyOfRange(offset - sz, offset), sz)
                                                try {
                                                    TtlHelper.setTtl(remoteSocket!!, rnd.nextInt(2, 4))
                                                    remoteOut.write(junk)
                                                    remoteOut.flush()
                                                    delay(rnd.nextLong(1, 3))
                                                    TtlHelper.setTtl(remoteSocket!!, 64)
                                                } catch (e: Throwable) {}
                                            }

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
                        when (buffer.size) { 8192 -> ProxyStats.release8k(buffer); 16384 -> ProxyStats.release16k(buffer); 65536 -> ProxyStats.release64k(buffer); else -> {} }
                        try { remoteSocket?.shutdownOutput() } catch (e: Throwable) {}
                    }
                }

                try {
                    coroutineScope {
                        val firstFinished = CompletableDeferred<Unit>()
                        remoteToClient.invokeOnCompletion { firstFinished.complete(Unit) }
                        clientToRemote.invokeOnCompletion { firstFinished.complete(Unit) }
                        firstFinished.await()
                    }
                } catch(e: Throwable) {}

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

    private suspend fun performSniGhosting(targetHost: String, vpnService: VpnService?) {
        val ghostTargets = listOf("google.com", "bing.com", "cloudflare.com", "apple.com", "microsoft.com")
        val target = ghostTargets.random()
        var socket: Socket? = null
        try {
            val ips = RobustResolver.resolve(target, vpnService)
            if (ips.isEmpty()) return
            
            socket = Socket()
            try { vpnService?.protect(socket) } catch (e: Throwable) {}
            socket.tcpNoDelay = true
            socket.soTimeout = 2000
            
            // Random temporal gap before ghosting
            delay(ThreadLocalRandom.current().nextLong(50, 200))
            
            // Use very low TTL to ensure it doesn't reach the real server but reaches the local/ISP DPI
            val discoveredTtl = AutoTtlProber.getDiscoveredTtl(targetHost) ?: 4
            TtlHelper.setTtl(socket, (discoveredTtl - 1).coerceAtLeast(2))
            
            socket.connect(InetSocketAddress(ips.random(), 443), 1500)
            val output = socket.getOutputStream()
            
            // Send a very convincing ClientHello
            val ghostHello = FakePacketHelper.buildChromeHello(target)
            output.write(ghostHello)
            output.flush()
            
            // Send some OOB data to further confuse state
            delay(ThreadLocalRandom.current().nextLong(10, 50))
            socket.sendUrgentData(ThreadLocalRandom.current().nextInt(256))
            
            // Delay a bit before closing to let DPI process it
            delay(ThreadLocalRandom.current().nextLong(20, 60))
        } catch (e: Throwable) {
        } finally {
            try { socket?.close() } catch (e: Throwable) {}
        }
        
        // Random gap between ghost and real handshake
        delay(ThreadLocalRandom.current().nextLong(100, 300))
    }

    private suspend fun applyWindowPulse(intensity: Int, rnd: ThreadLocalRandom) {
        if (intensity > 45 && rnd.nextInt(100) < (intensity / 5).coerceIn(5, 20)) {
            // Induce a small pause to force a TCP Window Update/Zero-Window advertisement from kernel
            delay(rnd.nextLong(1, 5))
        }
    }

    private fun applyWindowChaos(socket: Socket?, intensity: Int, rnd: ThreadLocalRandom) {
        if (socket == null || intensity < 50) return
        try {
            // Randomly vary the advertised window size by changing receive buffer size
            val base = if (intensity > 85) 16384 else 65536
            val chaos = rnd.nextInt(-2048, 2048)
            socket.receiveBufferSize = (base + chaos).coerceAtLeast(4096)
        } catch (e: Throwable) {}
    }

    private suspend fun connectToBestIp(
        ips: List<java.net.InetAddress>,
        port: Int,
        vpnService: VpnService?,
        config: SessionConfig,
        host: String
    ): Socket? {
        val channel = kotlinx.coroutines.channels.Channel<Socket>(ips.size)
        val activeJobs = mutableListOf<Job>()
        val attemptedSockets = java.util.concurrent.CopyOnWriteArrayList<Socket>()
        val censorship = ProxyStats.censorshipIntensity.value
        val attempted = if (censorship > 70) ips.size else minOf(ips.size, 3)
        val raceDelay = if (censorship > 70) 50L else 250L
        val failures = java.util.concurrent.atomic.AtomicInteger(0)
        val nextSignal = kotlinx.coroutines.channels.Channel<Unit>(1)
        
        return supervisorScope {
            for (i in 0 until attempted) {
                val ip = ips[i]
                activeJobs += launch(ProxyDispatcher.io) {
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
                            s.connect(InetSocketAddress(ip, port), connectTimeout)
                            val rtt = System.currentTimeMillis() - startConnect
                            ProxyStats.recordGlobalSuccess(rtt)
                            DnsCacheManager.recordIpSuccess(ip.hostAddress ?: "", rtt)
                        } catch (e: Throwable) {
                            nextSignal.trySend(Unit)
                            val elapsed = System.currentTimeMillis() - startConnect
                            val msg = e.message?.lowercase() ?: ""
                            DnsCacheManager.recordIpFailure(ip.hostAddress ?: "")
                            
                            val reason = when {
                                elapsed >= connectTimeout - 500 -> FailureReason.TIMEOUT
                                msg.contains("reset") -> FailureReason.TCP_RESET
                                msg.contains("refused") -> FailureReason.CONNECTION_REFUSED
                                else -> FailureReason.UNKNOWN
                            }
                            
                            if (reason == FailureReason.TIMEOUT) {
                                BypassConfig.recordDpiFailure(config.strategy, host, DpiType.CONNECTION_TIMEOUT)
                                BypassConfig.recordFailure(config.strategy, host, FailureReason.TIMEOUT)
                            } else if (reason == FailureReason.TCP_RESET) {
                                BypassConfig.recordDpiFailure(config.strategy, host, DpiType.TCP_RESET)
                                BypassConfig.recordFailure(config.strategy, host, FailureReason.TCP_RESET)
                            }
                            throw e
                        }
                        if (channel.trySend(s).isSuccess) {
                            // Successfully sent
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
                    val dynamicDelay = if (censorship > 85) (raceDelay / 2) else (raceDelay + i * 100L)
                    withTimeoutOrNull(dynamicDelay) {
                        nextSignal.receive()
                    }
                }
            }
            
            var winnerSocket: Socket? = null
            try {
                winnerSocket = withTimeoutOrNull(12000) { channel.receive() }
            } catch (e: Throwable) {} finally {
                channel.close()
                activeJobs.forEach { it.cancel() }
                attemptedSockets.forEach { s ->
                    if (s != winnerSocket) {
                        try { s.close() } catch (e: Throwable) {}
                    }
                }
            }
            winnerSocket
        }
    }

    private suspend fun startConfusionPulse(host: String, output: OutputStream, socket: Socket, scope: CoroutineScope) {
        scope.launch {
            val rnd = java.util.concurrent.ThreadLocalRandom.current()
            while (isActive && !socket.isClosed) {
                val intensity = ProxyStats.censorshipIntensity.value
                val baseDelay = if (intensity > 85) 10000L else 25000L
                delay(rnd.nextLong(baseDelay, baseDelay * 2)) 
                
                if (socket.isClosed) break
                try {
                    // 1. TCP OOB desync
                    socket.sendUrgentData(rnd.nextInt(256))
                    
                    // 2. Phantom SNI / Fake Header injection with low TTL
                    if (intensity > 55 && rnd.nextInt(100) < 50) {
                        val fakeSni = listOf("google.com", "cloudflare.com", "bing.com", "apple.com", "microsoft.com", "gstatic.com", "android.googleapis.com").random()
                        val fakeHandshake = if (rnd.nextBoolean()) FakePacketHelper.buildFakeTlsClientHello(fakeSni) else FakePacketHelper.buildHttpChaosPacket()
                        
                        TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
                        output.write(fakeHandshake)
                        output.flush()
                        delay(rnd.nextLong(1, 4))
                        TtlHelper.setTtl(socket, 64)
                    }
                    
                    // 3. Protocol-Compliant Noise (App-like traffic)
                    if (intensity > 70 && rnd.nextInt(100) < 40) {
                        val appNoise = when(rnd.nextInt(4)) {
                            0 -> "{\"status\":\"ok\",\"t\":${System.currentTimeMillis()}}".toByteArray()
                            1 -> byteArrayOf(0x00, 0x01, 0x00, 0x00, 0x00, 0x08) + ByteArray(8) { rnd.nextInt(256).toByte() } // Fake binary header
                            2 -> "HTTP/1.1 100 Continue\r\n\r\n".toByteArray()
                            else -> FakePacketHelper.buildTlsHeartbeat()
                        }
                        output.write(appNoise)
                        output.flush()
                    }

                    // 4. Advanced Zero-Window Probing (State Freeze)
                    if (intensity > 65 && rnd.nextInt(100) < 30) {
                        performZeroWindowProbe(socket, output)
                    }
                    
                    Log.v("TcpTransport", "High-frequency confusion pulse sent to $host (intensity $intensity)")
                } catch (e: Throwable) {
                    break
                }
            }
        }
    }
    private suspend fun performZeroWindowProbe(socket: Socket, out: java.io.OutputStream) {
        try {
            // 1. Freeze DPI state by setting window to 0
            TtlHelper.setWindowSize(socket, 0)
            
            // 2. Send 1-byte "probe" data (Keep-Alive like)
            out.write(byteArrayOf(ThreadLocalRandom.current().nextInt(256).toByte()))
            out.flush()
            
            // 3. Wait for DPI to process the 0-window state
            delay(ThreadLocalRandom.current().nextLong(50, 200))
            
            // 4. Restore window to a small value first to force small segments
            TtlHelper.setWindowSize(socket, ThreadLocalRandom.current().nextInt(128, 512))
            delay(10)
            
            // 5. Finally restore to normal
            TtlHelper.setWindowSize(socket, 65535)
        } catch (e: Throwable) {}
    }

    private fun oscillateWindowSize(socket: Socket, intensity: Int) {
        if (intensity < 60) return
        val rnd = ThreadLocalRandom.current()
        if (rnd.nextInt(100) < 30) {
            val smallWindow = rnd.nextInt(128, 2048)
            TtlHelper.setWindowSize(socket, smallWindow)
        } else {
            TtlHelper.setWindowSize(socket, 65535)
        }
    }

    private var lastGlobalCleanup = System.currentTimeMillis()
}
