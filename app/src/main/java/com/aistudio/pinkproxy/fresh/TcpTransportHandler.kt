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
        var throughputJob: Job? = null
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

            // SNI Ghosting
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
            val detectedSni = java.util.concurrent.atomic.AtomicReference<String?>(null)
            val writeMutex = Mutex()

            coroutineScope {
                // Forward from Remote to Client (Direct)
                val remoteToClient = launch(ProxyDispatcher.io) {
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

                // Forward from Client to Remote (with Bypass)
                val clientToRemote = launch(ProxyDispatcher.io) {
                    val buffer = ProxyStats.obtain64k()
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
                                val currentIntensity = ProxyStats.censorshipIntensity.value
                                packetsCount++
                                
                                val activeHost = detectedSni.get() ?: targetHost
                                
                                if (packetsCount <= 12) {
                                    if (packetsCount <= 2) {
                                        val sniOffset = TlsParser.findSniOffset(buffer, n)
                                        if (sniOffset != -1) {
                                            val realSni = TlsParser.extractHostname(buffer, n, sniOffset)
                                            if (realSni != null) detectedSni.set(realSni)
                                        }
                                    }
                                    
                                    writeMutex.lock()
                                    try {
                                        BypassConfig.applyBypass(remoteSocket, remoteOut, buffer, n, config, activeHost)
                                    } finally {
                                        writeMutex.unlock()
                                    }
                                } else {
                                    // Heavy Fragmentation
                                    if (currentIntensity > 50 && n > 1200) {
                                        var offset = 0
                                        while (offset < n) {
                                            val sz = minOf(512 + rnd.nextInt(512), n - offset)
                                            writeMutex.lock()
                                            try {
                                                remoteOut.write(buffer, offset, sz)
                                                remoteOut.flush()
                                            } finally {
                                                writeMutex.unlock()
                                            }
                                            offset += sz
                                            if (offset < n) delay(1)
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
                                }
                                totalWrittenClient.addAndGet(n.toLong())
                            }
                        }
                    } catch (e: Throwable) {
                        if (e !is CancellationException) Log.v("TcpTransport", "ClientToRemote error: ${e.message}")
                    } finally {
                        ProxyStats.release64k(buffer)
                        try { remoteSocket.shutdownOutput() } catch (e: Throwable) {}
                    }
                }

                // Confusion pulse
                launch {
                    val rnd = ThreadLocalRandom.current()
                    while (isActive) {
                        delay(rnd.nextLong(20000, 45000))
                        if (System.currentTimeMillis() - lastActivity.get() > 15000) {
                            writeMutex.lock()
                            try {
                                val originalTtl = TtlHelper.getSocketTtl(remoteSocket)
                                TtlHelper.setTtl(remoteSocket, rnd.nextInt(3, 7))
                                remoteOut.write(FakePacketHelper.buildTlsChaosPacket())
                                remoteOut.flush()
                                delay(10)
                                TtlHelper.setTtl(remoteSocket, originalTtl)
                            } catch (e: Throwable) {} finally {
                                writeMutex.unlock()
                            }
                        }
                    }
                }

                // Inactivity reaper
                launch {
                    while (isActive) {
                        delay(30000)
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
        ips.forEach { ip ->
            try {
                val s = Socket()
                vpnService?.protect(s)
                s.connect(InetSocketAddress(ip, port), 5000)
                return@withContext s
            } catch (e: Throwable) {}
        }
        null
    }

    private suspend fun performSniGhosting(host: String, vpnService: VpnService?) {
        // Implementation of SNI Ghosting
        try {
            val s = Socket()
            vpnService?.protect(s)
            val resolved = RobustResolver.resolve("google.com", vpnService)
            if (resolved.isNotEmpty()) {
                s.connect(InetSocketAddress(resolved.first(), 443), 2000)
                val out = s.getOutputStream()
                val hello = FakePacketHelper.buildRealisticTlsHello("google.com")
                TtlHelper.setTtl(s, 5)
                out.write(hello)
                out.flush()
                delay(10)
                s.close()
            }
        } catch (e: Throwable) {}
    }
}
