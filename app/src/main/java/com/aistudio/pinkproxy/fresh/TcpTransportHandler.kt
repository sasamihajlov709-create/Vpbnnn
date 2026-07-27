package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom
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
                    
                    for (i in 0 until attempted) {
                        val ip = resolved[i]
                        activeJobs += scope.launch(Dispatchers.IO) {
                            val s = Socket()
                            try {
                                vpnService?.protect(s)
                                s.tcpNoDelay = true
                                // Dynamic timeout based on RTT and Jitter
                                val baseTimeout = (BypassConfig.currentRttMs.value * 3).coerceIn(1500, 7000)
                                val jitter = ProxyStats.jitter.value
                                val connectTimeout = (baseTimeout + jitter).toInt().coerceIn(2000, 10000)
                                
                                val startConnect = System.currentTimeMillis()
                                try {
                                    s.connect(InetSocketAddress(ip, targetPort), connectTimeout)
                                    val rtt = System.currentTimeMillis() - startConnect
                                    ProxyStats.updateLatency(rtt)
                                    DnsCacheManager.recordIpSuccess(ip.hostAddress ?: "", rtt)
                                } catch (e: Exception) {
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
                            } catch (e: Exception) {
                                try { s.close() } catch (ex: Exception) {}
                                if (failures.incrementAndGet() == attempted) {
                                    channel.close()
                                }
                            }
                        }
                        if (i < attempted - 1) {
                            // Progressive race delay: prioritize top IPs
                            val dynamicDelay = if (censorship > 85) (raceDelay / 2) else (raceDelay + i * 100L)
                            delay(dynamicDelay)
                        }
                    }
                    val winner = try {
                        channel.receive()
                    } catch (e: Exception) {
                        throw Exception("All TCP connection attempts failed for $targetHost")
                    } finally {
                        channel.close()
                        activeJobs.forEach { it.cancel() }
                        while (true) {
                            val leftover = channel.tryReceive().getOrNull() ?: break
                            try { leftover.close() } catch (e: Exception) {}
                        }
                    }
                    winner
                }
            } catch (e: Exception) {
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
            } catch (e: Exception) {}

            val connectTime = System.currentTimeMillis() - start
            BypassConfig.TrafficShaper.updateRtt(connectTime)

            val clientIn = clientSocket.getInputStream()
            val clientOut = clientSocket.getOutputStream()
            val remoteIn = remoteSocket.getInputStream()
            val remoteOut = remoteSocket.getOutputStream()

            var lastActivity = System.currentTimeMillis()

            coroutineScope {
                // Keep-alive to prevent NAT/Firewall timeout with minimal noise
                val keepAliveJob = launch {
                    val rnd = ThreadLocalRandom.current()
                    while (isActive) {
                        delay(rnd.nextLong(30000, 60000))
                        if (System.currentTimeMillis() - lastActivity > 40000) {
                            try { 
                                if (ProxyStats.censorshipIntensity.value > 60) {
                                    // Send 1 byte of random noise
                                    remoteOut.write(rnd.nextInt(256))
                                    remoteOut.flush()
                                } else {
                                    remoteSocket?.sendUrgentData(0) 
                                }
                            } catch (e: Exception) {}
                        }
                    }
                }

                // Forward from Remote to Client (Direct)
                val remoteToClient = launch(Dispatchers.IO) {
                    val intensity = ProxyStats.censorshipIntensity.value
                    val activeConns = ProxyStats.activeConnections.value
                    val useSmallBuf = activeConns > 30 || intensity > 85
                    val buffer = if (useSmallBuf) ProxyStats.obtain16k() else ProxyStats.obtain64k()
                    
                    try {
                        var n: Int
                        var firstResponse = true
                        while (isActive) {
                            n = remoteIn.read(buffer)
                            if (n == -1) break
                            if (n > 0) {
                                if (firstResponse) {
                                    firstResponse = false
                                    val rtt = System.currentTimeMillis() - start
                                    BypassConfig.recordSuccess(strategy, rtt, targetHost)
                                    
                                    // Detect DPI blocks in payload
                                    if (n > 10) {
                                        val content = String(buffer, 0, n.coerceAtMost(200), Charsets.US_ASCII)
                                        if (content.contains("HTTP/1.1 403") || content.contains("Access Denied") || content.contains("Forbidden")) {
                                            ProxyStats.recordDpiEvent(DpiType.HTTP_BLOCK)
                                        }
                                        if (buffer[0] == 0x15.toByte()) { // TLS Alert
                                            ProxyStats.recordDpiEvent(DpiType.TLS_SNI_BLOCK)
                                        }
                                    }
                                }
                                
                                lastActivity = System.currentTimeMillis()
                                clientOut.write(buffer, 0, n)
                                clientOut.flush()
                                ProxyStats.updateBytes(n.toLong())
                                if (ProxyStats.censorshipIntensity.value > 85) yield()
                            }
                        }
                    } catch (e: Exception) {
                        val msg = e.message?.lowercase() ?: ""
                        if (System.currentTimeMillis() - start < 15000) {
                            BypassConfig.recordFailure(strategy, targetHost)
                        }
                        when {
                            msg.contains("reset") -> ProxyStats.recordDpiEvent(DpiType.TCP_RESET)
                            msg.contains("timeout") -> ProxyStats.recordDpiEvent(DpiType.CONNECTION_TIMEOUT)
                            else -> ProxyStats.recordCensorshipEvent(true)
                        }
                    } finally {
                        if (useSmallBuf) ProxyStats.release16k(buffer) else ProxyStats.release64k(buffer)
                        try { clientSocket.shutdownOutput() } catch (e: Exception) {}
                    }
                }

                // Forward from Client to Remote (with Bypass)
                val clientToRemote = launch(Dispatchers.IO) {
                    val intensity = ProxyStats.censorshipIntensity.value
                    val activeConns = ProxyStats.activeConnections.value
                    val useSmallBuf = activeConns > 30 || intensity > 85
                    val buffer = if (useSmallBuf) ProxyStats.obtain16k() else ProxyStats.obtain64k()
                    val rnd = ThreadLocalRandom.current()
                    
                    try {
                        var n: Int
                        var firstPacket = true
                        var totalWritten = 0L
                        while (isActive) {
                            n = clientIn.read(buffer)
                            if (n == -1) break
                            if (n > 0) {
                                lastActivity = System.currentTimeMillis()
                                if (firstPacket) {
                                    firstPacket = false
                                    try {
                                        BypassConfig.applyBypass(remoteSocket!!, remoteOut, buffer, n, config, targetHost)
                                    } catch (e: Exception) {
                                        BypassConfig.recordFailure(strategy, targetHost)
                                        throw e
                                    }
                                } else {
                                    val currentIntensity = ProxyStats.censorshipIntensity.value
                                    // Pacing: slow down if we just started or if censorship is high
                                    if (totalWritten < 32768 && currentIntensity > 50) {
                                        val pSize = if (currentIntensity > 80) 512 else 1024
                                        var offset = 0
                                        while (offset < n) {
                                            val chunk = minOf(pSize, n - offset)
                                            remoteOut.write(buffer, offset, chunk)
                                            remoteOut.flush()
                                            offset += chunk
                                            if (offset < n) delay(rnd.nextLong(2, 8))
                                        }
                                    } else if (currentIntensity > 65 && n > 1000) {
                                        val fragCount = if (currentIntensity > 90) 3 else 2
                                        val partSize = n / fragCount
                                        for (i in 0 until fragCount) {
                                            val offset = i * partSize
                                            val len = if (i == fragCount - 1) n - offset else partSize
                                            remoteOut.write(buffer, offset, len)
                                            remoteOut.flush()
                                            if (i < fragCount - 1) {
                                                val d = (BypassConfig.currentRttMs.value / 35 + 1).coerceAtMost(25)
                                                delay(d)
                                            }
                                        }
                                    } else {
                                        remoteOut.write(buffer, 0, n)
                                        remoteOut.flush()
                                    }
                                }
                                totalWritten += n
                                ProxyStats.updateBytes(n.toLong())
                            }
                        }
                    } catch (e: Exception) {
                        BypassConfig.TrafficShaper.recordError()
                        if (System.currentTimeMillis() - start < 15000) {
                            BypassConfig.recordFailure(strategy, targetHost)
                        }
                    } finally {
                        if (useSmallBuf) ProxyStats.release16k(buffer) else ProxyStats.release64k(buffer)
                        try { remoteSocket?.shutdownOutput() } catch (e: Exception) {}
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
                
                try { clientSocket.close() } catch(e: Exception) {}
                try { remoteSocket?.close() } catch(e: Exception) {}
                
                keepAliveJob.cancel()
                remoteToClient.cancel()
                clientToRemote.cancel()
            }
        } catch (e: Exception) {
            Log.v("TcpTransport", "Session $targetHost:$targetPort failed: ${e.message}")
        } finally {
            try { clientSocket.close() } catch (e: Exception) {}
            try { remoteSocket?.close() } catch (e: Exception) {}
        }
    }
}
