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
            val totalWrittenClient = AtomicLong(0)
            val isTls = targetPort == 443 || targetPort == 8443

            val censorship = BypassConfig.censorshipLevel.value
            var strategy = BypassConfig.getBestStrategyForHost(targetHost)
            var config = BypassConfig.getSessionConfig(targetHost, strategy, BypassConfig.currentRttMs.value)

            // SNI Ghosting: Send fake TLS Hello with low TTL to distract DPI
            if (censorship > 65 && isTls) {
                scope.launch(ProxyDispatcher.io) {
                    performSniGhosting(targetHost, vpnService)
                }
            }

            remoteSocket = connectToBestIp(resolved, targetPort, vpnService, config, targetHost)
            if (remoteSocket == null) {
                clientSocket.close()
                return
            }

            remoteSocket.tcpNoDelay = true
            val clientIn = clientSocket.getInputStream()
            val clientOut = clientSocket.getOutputStream()
            val remoteIn = remoteSocket.getInputStream()
            val remoteOut = remoteSocket.getOutputStream()
            
            val lastActivity = AtomicLong(System.currentTimeMillis())
            val detectedSni = AtomicReference<String?>(null)
            val writeMutex = Mutex()
            
            // Adaptive buffer size based on RTT
            val rtt = BypassConfig.currentRttMs.value
            val transportBufferSize = when {
                rtt > 500 -> 4096
                rtt > 200 -> 8192
                else -> 16384
            }

            coroutineScope {
                // Forward from Remote to Client (Direct)
                launch(ProxyDispatcher.io) {
                    val buffer = ProxyStats.obtain16k()
                    try {
                        var n: Int
                        while (isActive) {
                            remoteSocket.soTimeout = 60000
                            n = remoteIn.read(buffer)
                            if (n == -1) break
                            if (n > 0) {
                                lastActivity.set(System.currentTimeMillis())
                                clientOut.write(buffer, 0, n)
                                clientOut.flush()
                                ProxyStats.updateBytes(n.toLong())
                            }
                        }
                    } catch (e: Throwable) {
                        if (e !is CancellationException) Log.v("TcpTransport", "RemoteToClient error: ${e.message}")
                    } finally {
                        ProxyStats.release16k(buffer)
                        try { clientSocket.shutdownOutput() } catch (e: Throwable) {}
                    }
                }

                // Forward from Client to Remote (with Bypass & Advanced Evasion)
                launch(ProxyDispatcher.io) {
                    val buffer = ProxyStats.obtain16k()
                    val rnd = ThreadLocalRandom.current()
                    var packetsCount = 0
                    try {
                        var n: Int
                        while (isActive) {
                            clientSocket.soTimeout = 60000
                            n = clientIn.read(buffer)
                            if (n == -1) break
                            if (n > 0) {
                                lastActivity.set(System.currentTimeMillis())
                                val intensity = ProxyStats.censorshipIntensity.value
                                packetsCount++
                                
                                val activeHost = detectedSni.get() ?: targetHost
                                
                                if (intensity > 85 && packetsCount == 1 && n > 5) {
                                    // Extreme 1-byte fragmentation for the start of TLS/HTTP session
                                    // This often bypasses DPI that waits for the full ClientHello
                                    writeMutex.lock()
                                    try {
                                        remoteOut.write(buffer[0].toInt())
                                        remoteOut.flush()
                                        delay(rnd.nextLong(2, 10))
                                        remoteOut.write(buffer, 1, n - 1)
                                        remoteOut.flush()
                                    } finally {
                                        writeMutex.unlock()
                                    }
                                    continue
                                }

                                if (packetsCount <= 12) {
                                    // Try to extract SNI if it's a TLS handshake
                                    if (packetsCount <= 3) {
                                        val sniOffset = TlsParser.findSniOffset(buffer, n)
                                        if (sniOffset != -1) {
                                            val realSni = TlsParser.extractHostname(buffer, n, sniOffset)
                                            if (realSni != null) detectedSni.set(realSni)
                                        }
                                    }
                                    
                                    // Extreme evasion: Sequence Desync before critical packets
                                    if (intensity > 80 && packetsCount < 5) {
                                        sendSequenceDesync(remoteSocket, rnd)
                                    }

                                    // Apply standard BypassConfig strategies
                                    writeMutex.lock()
                                    try {
                                        BypassConfig.applyBypass(remoteSocket, remoteOut, buffer, n, config, activeHost)
                                    } finally {
                                        writeMutex.unlock()
                                    }
                                } else {
                                    // Post-Handshake Evasion: Fragmentation and Chaos
                                    if (intensity > 40) {
                                        // Periodic Window Oscillation to confuse stateful DPI
                                        if (packetsCount % 13 == 0) {
                                            oscillateWindowSize(remoteSocket)
                                        }

                                        // Advanced fragmentation for large payloads
                                        if (n > 800) {
                                            var offset = 0
                                            while (offset < n) {
                                                val sz = if (intensity > 75) 
                                                    rnd.nextInt(32, 256).coerceAtMost(n - offset)
                                                else 
                                                    rnd.nextInt(128, 768).coerceAtMost(n - offset)
                                                
                                                writeMutex.lock()
                                                try {
                                                    // In extreme cases, inject a tiny junk segment with low TTL before the real fragment
                                                    if (intensity > 85 && rnd.nextInt(100) < 35) {
                                                        injectGhostSegment(remoteSocket, remoteOut, rnd)
                                                    }
                                                    
                                                    remoteOut.write(buffer, offset, sz)
                                                    remoteOut.flush()
                                                } finally {
                                                    writeMutex.unlock()
                                                }
                                                offset += sz
                                                // Staggered delay for high-intensity evasion
                                                if (offset < n) delay(if (intensity > 80) rnd.nextLong(2, 8) else rnd.nextLong(1, 3))
                                            }
                                        } else {
                                            writeMutex.lock()
                                            try {
                                                remoteOut.write(buffer, 0, n)
                                                remoteOut.flush()
                                            } finally {
                                                writeMutex.unlock()
                                            }
                                        }
                                    } else {
                                        // Standard direct forwarding
                                        writeMutex.lock()
                                        try {
                                            remoteOut.write(buffer, 0, n)
                                            remoteOut.flush()
                                        } finally {
                                            writeMutex.unlock()
                                        }
                                    }
                                }
                                totalWrittenClient.addAndGet(n.toLong())
                            }
                        }
                    } catch (e: Throwable) {
                        if (e !is CancellationException) Log.v("TcpTransport", "ClientToRemote error: ${e.message}")
                    } finally {
                        ProxyStats.release16k(buffer)
                        try { remoteSocket.shutdownOutput() } catch (e: Throwable) {}
                    }
                }

                // Idle Smuggling (PSH-1): Send 1-byte PSH during inactivity to keep DPI state active
                launch {
                    val rnd = ThreadLocalRandom.current()
                    while (isActive) {
                        delay(rnd.nextLong(25000, 40000))
                        
                        if (System.currentTimeMillis() - lastActivity.get() > 20000) {
                            writeMutex.lock()
                            try {
                                // Idle Smuggling pulse removed sendUrgentData to avoid TCP OOB stream corruption
                                Log.v("TcpTransport", "Idle keep-alive pulse for $targetHost")
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
                        // Adaptive delay based on censorship intensity
                        val delayMs = when {
                            ProxyStats.censorshipIntensity.value > 85 -> rnd.nextLong(12000, 20000)
                            ProxyStats.censorshipIntensity.value > 50 -> rnd.nextLong(18000, 35000)
                            else -> rnd.nextLong(35000, 70000)
                        }
                        delay(delayMs)
                        
                        // Only pulse if the connection has been idle for a while, to avoid interference
                        if (System.currentTimeMillis() - lastActivity.get() > 12000) {
                            writeMutex.lock()
                            try {
                                sendConfusionPacket(remoteSocket, remoteOut, rnd)
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
                        if (ProxyStats.censorshipIntensity.value > 30) {
                            applyWindowPulse(remoteSocket)
                        }
                    }
                }

                // Inactivity reaper
                launch {
                    while (isActive) {
                        delay(30000)
                        // If no activity for 5 minutes, close the session
                        if (System.currentTimeMillis() - lastActivity.get() > 300000) {
                            this@coroutineScope.cancel("Idle")
                        }
                    }
                }
            }
        } catch (e: Throwable) {
            Log.v("TcpTransport", "Session failed: ${e.message}")
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
                    s.tcpNoDelay = true
                    
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
            result = withTimeoutOrNull(8000) { channel.receive() }
        } catch (e: Throwable) {
        } finally {
            jobs.forEach { it.cancel() }
            channel.close()
            while (true) {
                val s = channel.tryReceive().getOrNull() ?: break
                try { s.close() } catch (e: Throwable) {}
            }
        }
        result
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
                
                // Target the censor hop exactly if known, else use a very low TTL
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
            val current = socket.receiveBufferSize
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
        } catch (e: Throwable) {}
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
        } catch (e: Throwable) {}
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
        } catch (e: Throwable) {}
    }

    private suspend fun sendSequenceDesync(socket: Socket, rnd: ThreadLocalRandom) {
        try {
            TtlHelper.setWindowSize(socket, 0)
            delay(rnd.nextLong(2, 10))
            TtlHelper.setWindowSize(socket, 65535)
        } catch (e: Throwable) {}
    }
}
