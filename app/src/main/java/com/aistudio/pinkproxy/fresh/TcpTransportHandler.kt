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

    suspend fun handleTcpSession(
        clientSocket: Socket,
        targetHost: String,
        targetPort: Int,
        vpnService: VpnService?,
        scope: CoroutineScope
    ) {
        var remoteSocket: Socket? = null
        ProxyStats.updateConnections(1)
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
                    
                    for (i in 0 until attempted) {
                        val ip = resolved[i]
                        activeJobs += scope.launch(Dispatchers.IO) {
                            val s = Socket()
                            try {
                                vpnService?.protect(s)
                                s.tcpNoDelay = true
                                // Dynamic timeout based on RTT
                                val connectTimeout = (BypassConfig.currentRttMs.value * 4).coerceIn(2000, 8000).toInt()
                                s.connect(InetSocketAddress(ip, targetPort), connectTimeout)
                                if (!channel.isClosedForSend) {
                                    channel.trySend(s)
                                } else {
                                    s.close()
                                }
                            } catch (e: Exception) {
                                try { s.close() } catch (ex: Exception) {}
                            }
                        }
                        if (i < attempted - 1) delay(raceDelay) // Staggered start
                    }

                    val winner = try {
                        channel.receive()
                    } catch (e: Exception) {
                        throw Exception("All TCP connection attempts failed for $targetHost")
                    } finally {
                        channel.close()
                        activeJobs.forEach { it.cancel() }
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
                // Keep-alive to prevent NAT/Firewall timeout
                val keepAliveJob = launch {
                    while (isActive) {
                        delay(45000)
                        if (System.currentTimeMillis() - lastActivity > 40000) {
                            try { remoteSocket?.sendUrgentData(0) } catch (e: Exception) {}
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
                        while (isActive) {
                            n = remoteIn.read(buffer)
                            if (n == -1) break
                            if (n > 0) {
                                lastActivity = System.currentTimeMillis()
                                // Downstream Fragmentation: Help against local downstream DPI
                                if (ProxyStats.censorshipIntensity.value > 92 && n > 800) {
                                    val part = n / 2
                                    clientOut.write(buffer, 0, part)
                                    clientOut.flush()
                                    delay(1)
                                    clientOut.write(buffer, part, n - part)
                                } else {
                                    clientOut.write(buffer, 0, n)
                                }
                                clientOut.flush()
                                ProxyStats.updateBytes(n.toLong())
                                if (ProxyStats.censorshipIntensity.value > 85) yield()
                            }
                        }
                    } catch (e: Exception) {
                    } finally {
                        if (useSmallBuf) ProxyStats.release16k(buffer) else ProxyStats.release64k(buffer)
                        try { clientSocket.shutdownOutput() } catch (e: Exception) {}
                        try { clientSocket.close() } catch (e: Exception) {}
                    }
                }

                // Forward from Client to Remote (with Bypass)
                val clientToRemote = launch(Dispatchers.IO) {
                    val intensity = ProxyStats.censorshipIntensity.value
                    val activeConns = ProxyStats.activeConnections.value
                    val useSmallBuf = activeConns > 30 || intensity > 85
                    val buffer = if (useSmallBuf) ProxyStats.obtain16k() else ProxyStats.obtain64k()
                    
                    try {
                        var n: Int
                        var firstPacket = true
                        while (isActive) {
                            n = clientIn.read(buffer)
                            if (n == -1) break
                            if (n > 0) {
                                lastActivity = System.currentTimeMillis()
                                if (firstPacket) {
                                    firstPacket = false
                                    val startBypass = System.currentTimeMillis()
                                    try {
                                        BypassConfig.applyBypass(remoteSocket!!, remoteOut, buffer, n, config, targetHost)
                                        BypassConfig.recordSuccess(strategy, System.currentTimeMillis() - startBypass, targetHost)
                                    } catch (e: Exception) {
                                        BypassConfig.recordFailure(strategy, targetHost)
                                        throw e
                                    }
                                } else {
                                    if (ProxyStats.censorshipIntensity.value > 65 && n > 1100) {
                                        val mid = n / 2
                                        remoteOut.write(buffer, 0, mid)
                                        remoteOut.flush()
                                        delay(BypassConfig.currentRttMs.value / 25 + 1)
                                        remoteOut.write(buffer, mid, n - mid)
                                    } else {
                                        remoteOut.write(buffer, 0, n)
                                    }
                                    remoteOut.flush()
                                }
                                ProxyStats.updateBytes(n.toLong())
                            }
                        }
                    } catch (e: Exception) {
                        BypassConfig.TrafficShaper.recordError()
                    } finally {
                        if (useSmallBuf) ProxyStats.release16k(buffer) else ProxyStats.release64k(buffer)
                        try { remoteSocket?.shutdownOutput() } catch (e: Exception) {}
                    }
                }

                select<Unit> {
                    remoteToClient.onJoin {}
                    clientToRemote.onJoin {}
                }
                
                keepAliveJob.cancel()
                remoteToClient.cancel()
                clientToRemote.cancel()
            }
        } catch (e: Exception) {
            Log.v("TcpTransport", "Session $targetHost:$targetPort failed: ${e.message}")
        } finally {
            ProxyStats.updateConnections(-1)
            try { clientSocket.close() } catch (e: Exception) {}
            try { remoteSocket?.close() } catch (e: Exception) {}
        }
    }
}
