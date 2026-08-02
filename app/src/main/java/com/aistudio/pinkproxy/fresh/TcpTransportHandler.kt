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
                                        sendSequenceDesync(remoteSocket, remoteOut, rnd)
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
                                // Send 1 byte of urgent or dummy data with low TTL
                                val oldTtl = TtlHelper.getSocketTtl(remoteSocket)
                                val discoveredTtl = AutoTtlProber.getDiscoveredTtl("global") ?: 5
                                
                                TtlHelper.setTtl(remoteSocket, discoveredTtl)
                                // Urgent data or just a dummy PSH segment
                                remoteSocket.sendUrgentData(rnd.nextInt(256))
                                delay(1)
                                TtlHelper.setTtl(remoteSocket, oldTtl)
                                
                                Log.v("TcpTransport", "Idle Smuggling pulse sent for $targetHost")
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
            try {
                val s = Socket()
                vpnService?.protect(s)
                s.connect(InetSocketAddress(ips[0], port), 5000)
                return@withContext s
            } catch (e: Throwable) { return@withContext null }
        }

        // Happy Eyeballs: Connect to multiple IPs in parallel and take the first one
        val channel = kotlinx.coroutines.channels.Channel<Socket>(ips.size)
        val jobs = mutableListOf<Job>()
        val completedCount = java.util.concurrent.atomic.AtomicInteger(0)
        
        ips.take(6).forEachIndexed { index, ip ->
            jobs += launch {
                try {
                    // Stagger connections: 250ms delay between attempts to avoid network burst
                    if (index > 0) delay(index * 250L)
                    val s = Socket()
                    vpnService?.protect(s)
                    s.tcpNoDelay = true
                    s.connect(InetSocketAddress(ip, port), 6000)
                    if (!channel.isClosedForSend) {
                        channel.send(s)
                    } else {
                        s.close()
                    }
                } catch (e: Throwable) {
                    if (completedCount.incrementAndGet() == ips.size) {
                        channel.close()
                    }
                }
            }
        }
        
        var result: Socket? = null
        try {
            result = withTimeoutOrNull(10000) { channel.receive() }
        } catch (e: Throwable) {
        } finally {
            jobs.forEach { it.cancel() }
            channel.close()
            // Close any sockets that were received after we got our result
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
                val discoveredTtl = AutoTtlProber.getDiscoveredTtl(decoy) ?: 4
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

    private fun applyWindowPulse(socket: Socket) {
        try {
            val rnd = ThreadLocalRandom.current()
            val original = socket.receiveBufferSize
            socket.receiveBufferSize = 1
            // Small delay is not possible in blocking IO without a read/write, 
            // but changing the buffer size affects future ACKs sent by the kernel.
            socket.receiveBufferSize = original
        } catch (e: Throwable) {}
    }

    private suspend fun sendConfusionPacket(socket: Socket, out: OutputStream, rnd: ThreadLocalRandom) {
        try {
            val discoveredTtl = AutoTtlProber.getDiscoveredTtl("global") ?: 5
            val originalTtl = TtlHelper.getSocketTtl(socket)
            
            // Send multiple tiny chaos packets with low TTL
            TtlHelper.setTtl(socket, discoveredTtl)
            
            val packet = when(rnd.nextInt(3)) {
                0 -> FakePacketHelper.buildTlsChaosPacket()
                1 -> FakePacketHelper.buildHttpChaosPacket()
                else -> FakePacketHelper.buildUdpNoise(rnd.nextInt(16, 64))
            }
            
            out.write(packet)
            out.flush()
            delay(5)
            
            // Restore TTL for real traffic
            TtlHelper.setTtl(socket, originalTtl)
        } catch (e: Throwable) {}
    }

    private suspend fun injectGhostSegment(socket: Socket, out: OutputStream, rnd: ThreadLocalRandom) {
        try {
            val discoveredTtl = AutoTtlProber.getDiscoveredTtl("global") ?: 4
            val oldTtl = TtlHelper.getSocketTtl(socket)
            
            TtlHelper.setTtl(socket, discoveredTtl)
            val junk = FakePacketHelper.buildUdpNoise(rnd.nextInt(8, 32))
            out.write(junk)
            out.flush()
            delay(1)
            
            TtlHelper.setTtl(socket, oldTtl)
        } catch (e: Throwable) {}
    }

    private suspend fun sendSequenceDesync(socket: Socket, out: OutputStream, rnd: ThreadLocalRandom) {
        try {
            // Sequence Number Desync: Send 1 byte of urgent data or low-TTL junk
            // This forces DPI to track sequence numbers more strictly, often leading to state exhaustion or bypass
            val oldTtl = TtlHelper.getSocketTtl(socket)
            val discoveredTtl = AutoTtlProber.getDiscoveredTtl("global") ?: 5
            
            TtlHelper.setTtl(socket, discoveredTtl)
            socket.sendUrgentData(rnd.nextInt(256))
            out.write(FakePacketHelper.buildUdpNoise(rnd.nextInt(4, 16)))
            out.flush()
            delay(1)
            TtlHelper.setTtl(socket, oldTtl)
        } catch (e: Throwable) {}
    }
}
