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
            remoteSocket = try {
                withTimeout(12000) {
                    val channel = kotlinx.coroutines.channels.Channel<Socket>(resolved.size)
                    val activeJobs = mutableListOf<Job>()
                    // Aggressive racing: attempt more IPs if censorship is high
                    val attempted = if (censorship > 70) resolved.size else minOf(resolved.size, 3)
                    val raceDelay = if (censorship > 70) 50L else 250L
                    val failures = java.util.concurrent.atomic.AtomicInteger(0)
                    val nextSignal = kotlinx.coroutines.channels.Channel<Unit>(1)
                    
                    for (i in 0 until attempted) {
                        val ip = resolved[i]
                        activeJobs += scope.launch(ProxyDispatcher.io) {
                            val s = Socket()
                            try {
                                try { vpnService?.protect(s) } catch (e: Throwable) {}
                                s.tcpNoDelay = true
                                try { s.sendBufferSize = 128 * 1024 } catch (e: Throwable) {}
                                try { s.receiveBufferSize = 128 * 1024 } catch (e: Throwable) {}
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
                                    if (elapsed >= connectTimeout - 500) {
                                        BypassConfig.recordDpiFailure(strategy, targetHost, DpiType.CONNECTION_TIMEOUT)
                                    } else if (msg.contains("reset")) {
                                        BypassConfig.recordDpiFailure(strategy, targetHost, DpiType.TCP_RESET)
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
                            val dynamicDelay = if (censorship > 85) (raceDelay / 2) else (raceDelay + i * 100L)
                            withTimeoutOrNull(dynamicDelay) {
                                nextSignal.receive()
                            }
                        }
                    }
                    val winner = try {
                        channel.receive()
                    } catch (e: Throwable) {
                        throw Exception("All TCP connection attempts failed for $targetHost")
                    } finally {
                        channel.close()
                        activeJobs.forEach { it.cancel() }
                        while (true) {
                            val leftover = channel.tryReceive().getOrNull() ?: break
                            try { leftover.close() } catch (e: Throwable) {}
                        }
                    }
                    winner
                }
            } catch (e: Throwable) {
                Log.w("TcpTransport", "Connection failed to $targetHost: ${e.message}")
                clientSocket.close()
                return
            }

            // Optimization: Reset timeouts and enable TCP_NODELAY for both ends of the tunnel
            try {
                clientSocket.soTimeout = 0
                remoteSocket.soTimeout = 0
                remoteSocket.tcpNoDelay = true
                
                val intensity = ProxyStats.censorshipIntensity.value
                val bufSize = if (intensity > 88) 16384 else if (intensity > 70) 32768 else 128 * 1024
                
                remoteSocket.sendBufferSize = 128 * 1024
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
                    
                    // Adaptive buffer size: small for high intensity, large for high speed
                    val buffer = when {
                        intensity > 90 || activeConns > 100 -> ProxyStats.obtain8k()
                        intensity > 70 || activeConns > 40 -> ProxyStats.obtain16k()
                        speed > 512 * 1024 -> ProxyStats.obtain64k()
                        else -> ProxyStats.obtain16k()
                    }
                    val bufSize = buffer.size
                    
                    try {
                        var n: Int
                        var firstResponse = true
                        while (isActive) {
                            try {
                                remoteSocket?.soTimeout = 15000
                                n = remoteIn.read(buffer)
                            } catch (e: Throwable) {
                                if (e is java.io.InterruptedIOException || e is java.net.SocketTimeoutException) {
                                    if (isActive) continue else break
                                }
                                throw e
                            }
                            if (n == -1) break
                            if (n > 0) {
                                if (firstResponse) {
                                    firstResponse = false
                                    val rtt = System.currentTimeMillis() - start
                                    BypassConfig.recordSuccess(strategy, rtt, targetHost)
                                    
                                    // Detect DPI blocks in payload
                                    if (n > 10) {
                                        if (buffer[0] == 0x15.toByte()) { // TLS Alert
                                            ProxyStats.recordDpiEvent(DpiType.TLS_SNI_BLOCK)
                                        } else {
                                            // Fast byte-level scan for HTTP 403 / Forbidden
                                            var foundBlock = false
                                            val scanLen = n.coerceAtMost(200)
                                            for (i in 0 until scanLen - 12) {
                                                if (buffer[i] == 'H'.code.toByte() && buffer[i+1] == 'T'.code.toByte() && buffer[i+9] == '4'.code.toByte() && buffer[i+10] == '0'.code.toByte() && buffer[i+11] == '3'.code.toByte()) { foundBlock = true; break }
                                                if (buffer[i] == 'F'.code.toByte() && buffer[i+1] == 'o'.code.toByte() && buffer[i+2] == 'r'.code.toByte() && buffer[i+3] == 'b'.code.toByte() && buffer[i+4] == 'i'.code.toByte() && buffer[i+5] == 'd'.code.toByte() && buffer[i+6] == 'd'.code.toByte() && buffer[i+7] == 'e'.code.toByte() && buffer[i+8] == 'n'.code.toByte()) { foundBlock = true; break }
                                            }
                                            if (foundBlock) {
                                                ProxyStats.recordDpiEvent(DpiType.HTTP_BLOCK)
                                            }
                                        }
                                    }
                                }
                                
                                lastActivity.set(System.currentTimeMillis())
                                clientOut.write(buffer, 0, n)
                                clientOut.flush()
                                ProxyStats.updateBytes(n.toLong())
                                
                                // Traffic Shaping: if congestion window is low, throttle slightly
                                val cwnd = ProxyStats.congestionWindow.value
                                if (cwnd < 20 && intensity > 50) {
                                    val delay = (1000L / cwnd).coerceAtMost(50)
                                    delay(delay)
                                } else if (intensity > 85) {
                                    yield()
                                }
                            }
                        }
                    } catch (e: Throwable) {
                        if (e is CancellationException) throw e
                        val msg = e.message?.lowercase() ?: ""
                        if (System.currentTimeMillis() - start < 15000) {
                            BypassConfig.recordFailure(strategy, targetHost)
                        }
                        when {
                            msg.contains("reset") -> {
                                ProxyStats.recordDpiEvent(DpiType.TCP_RESET)
                                if (totalWrittenClient.get() > 0 && totalWrittenClient.get() < 5000) ProxyStats.recordMssFailure()
                            }
                            msg.contains("timeout") -> ProxyStats.recordDpiEvent(DpiType.CONNECTION_TIMEOUT)
                            else -> ProxyStats.recordCensorshipEvent(true)
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
                    val intensity = ProxyStats.censorshipIntensity.value
                    val activeConns = ProxyStats.activeConnections.value
                    val useSmallBuf = activeConns > 30 || intensity > 85
                    val buffer = if (useSmallBuf) ProxyStats.obtain16k() else ProxyStats.obtain64k()
                    val rnd = ThreadLocalRandom.current()
                    
                    try {
                        var n: Int
                        var firstPacket = true
                        while (isActive) {
                            try {
                                n = clientIn.read(buffer)
                            } catch (e: Throwable) {
                                if (e is java.io.InterruptedIOException || e is java.net.SocketTimeoutException) {
                                    if (isActive) continue else break
                                }
                                throw e
                            }
                            if (n == -1) break
                            if (n > 0) {
                                lastActivity.set(System.currentTimeMillis())
                                val currentIntensity = ProxyStats.censorshipIntensity.value
                                
                                if (firstPacket) {
                                    firstPacket = false
                                    try {
                                        BypassConfig.applyBypass(remoteSocket!!, remoteOut, buffer, n, config, targetHost)
                                    } catch (e: Throwable) {
                                        if (e is CancellationException) throw e
                                        BypassConfig.recordFailure(strategy, targetHost)
                                        throw e
                                    }
                                } else if (currentIntensity > 65 && n > 2) {
                                    // Opportunistic Fragmentation for DPI evasion
                                    if (rnd.nextInt(100) < (currentIntensity - 50)) {
                                        val split = rnd.nextInt(1, n)
                                        remoteOut.write(buffer, 0, split)
                                        remoteOut.flush()
                                        delay(rnd.nextLong(1, 4))
                                        remoteOut.write(buffer, split, n - split)
                                        remoteOut.flush()
                                    } else {
                                        remoteOut.write(buffer, 0, n)
                                        remoteOut.flush()
                                    }
                                } else {
                                    // Pacing and standard fragmentation
                                    val mss = ProxyStats.maxMss.value
                                    if (totalWrittenClient.get() < 32768 && currentIntensity > 50) {
                                        val pSize = if (currentIntensity > 80) minOf(512, mss) else minOf(1024, mss)
                                        var offset = 0
                                        while (offset < n && isActive) {
                                            val chunk = minOf(pSize, n - offset)
                                            remoteOut.write(buffer, offset, chunk)
                                            remoteOut.flush()
                                            offset += chunk
                                            if (offset < n) delay(rnd.nextLong(2, 8))
                                        }
                                    } else if (currentIntensity > 75 && n > 1000) {
                                        val fragCount = if (currentIntensity > 90) 3 else 2
                                        val partSize = n / fragCount
                                        for (i in 0 until fragCount) {
                                            if (!isActive) break
                                            val offset = i * partSize
                                            val len = if (i == fragCount - 1) n - offset else partSize
                                            remoteOut.write(buffer, offset, len)
                                            remoteOut.flush()
                                            if (i < fragCount - 1) delay(rnd.nextLong(5, 15))
                                        }
                                    } else {
                                        remoteOut.write(buffer, 0, n)
                                        if (strategy == BypassStrategy.TCP_RANDOM_PADDING && rnd.nextInt(100) < 30) {
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
                        if (useSmallBuf) ProxyStats.release16k(buffer) else ProxyStats.release64k(buffer)
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
        }
    }
}
