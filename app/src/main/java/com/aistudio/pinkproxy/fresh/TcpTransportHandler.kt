package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import java.io.InputStream
import java.io.OutputStream
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
        val sessionId = "tcp_${System.currentTimeMillis()}_${ThreadLocalRandom.current().nextInt(1000, 9999)}"
        var remoteSocket: Socket? = null
        var remoteIn: InputStream? = null
        var remoteOut: OutputStream? = null
        try {
            TcpTransportManager.configureSocket(clientSocket)

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
            val strategy = forcedStrategy ?: BypassConfig.getBestStrategyForHost(targetHost)
            ProxyStats.registerFlow(sessionId, targetHost, "TCP", strategy)
            
            val totalWrittenClient = AtomicLong(0)
            val isTls = targetPort == 443 || targetPort == 8443

            val censorship = BypassConfig.censorshipLevel
            val config = BypassConfig.getSessionConfig(targetHost, strategy, BypassConfig.currentRttMs.value)

            if (censorship > 65 && isTls) {
                scope.launch(ProxyDispatcher.io) {
                    TcpTransportManager.performSniGhosting(targetHost, vpnService)
                }
            }

            val clientIn = clientSocket.getInputStream()
            val clientOut = clientSocket.getOutputStream()
            
            val lastActivity = AtomicLong(System.currentTimeMillis())
            val writeMutex = Mutex()
            
            val rtt = BypassConfig.currentRttMs.value
            val intensity = ProxyStats.censorshipIntensity.value
            val transportBufferSize = when {
                intensity > 80 -> 4096
                rtt > 500 -> 8192
                rtt > 200 -> 16384
                else -> 32768
            }

            val firstClientPacket = ByteArray(transportBufferSize)
            clientSocket.soTimeout = 3000
            var firstClientPacketLen = 0
            try {
                firstClientPacketLen = clientIn.read(firstClientPacket)
            } catch (e: Throwable) {
                Log.v("TcpTransport", "Initial client read failed (might be normal): ${e.message}")
            }

            if (firstClientPacketLen <= 0) {
                // If we can't read anything initially, it might be a server-first protocol or just slow client.
                // For HTTPS it shouldn't happen usually.
                remoteSocket = TcpTransportManager.connectToBestIp(resolved, targetPort, vpnService, config, targetHost)
            } else {
                val raceResult = TcpRaceConnector.racingConnect(
                    resolved, targetPort, vpnService, targetHost, 
                    strategy, BypassConfig.getFallbackStrategy(strategy),
                    firstClientPacket, firstClientPacketLen, transportBufferSize
                )
                
                if (raceResult != null) {
                    remoteSocket = raceResult.socket
                    remoteIn = raceResult.input
                    remoteOut = raceResult.output
                    // Write back the first response we got during racing
                    clientOut.write(raceResult.firstResponse, 0, raceResult.firstResponseLen)
                    clientOut.flush()
                } else {
                    remoteSocket = TcpTransportManager.connectToBestIp(resolved, targetPort, vpnService, config, targetHost)
                }
            }

            if (remoteSocket == null) {
                onConnectFailure?.invoke("CONNECT_FAILED")
                return
            }
            
            val finalRemoteSocket = remoteSocket
            remoteIn = remoteIn ?: finalRemoteSocket.getInputStream()
            remoteOut = remoteOut ?: finalRemoteSocket.getOutputStream()
            val finalRemoteIn = remoteIn!!
            val finalRemoteOut = remoteOut!!

            onConnectSuccess?.invoke()

            coroutineScope {
                // Keep-alive pulse
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
                            } catch (e: Throwable) {
                                Log.v("TcpTransport", "Idle pulse failed: ${e.message}")
                            } finally {
                                writeMutex.unlock()
                            }
                        }
                    }
                }

                // Data pump jobs
                val remoteToClientJob = launch {
                    try {
                        val buffer = ByteArray(transportBufferSize)
                        while (isActive) {
                            val read = finalRemoteIn.read(buffer)
                            if (read == -1) break
                            lastActivity.set(System.currentTimeMillis())
                            if (intensity > 70 && ThreadLocalRandom.current().nextInt(100) < 5) {
                                TcpTransportManager.oscillateWindowSize(clientSocket)
                            }
                            clientOut.write(buffer, 0, read)
                            clientOut.flush()
                            ProxyStats.recordStats(sessionId, 0, read.toLong())
                        }
                    } catch (e: Throwable) {
                        Log.v("TcpTransport", "Remote to client pump failed: ${e.message}")
                    } finally {
                        try { clientSocket.close() } catch (e: Throwable) {}
                    }
                }

                try {
                    // Send remaining data
                    val buffer = ByteArray(transportBufferSize)
                    while (isActive) {
                        val read = clientIn.read(buffer)
                        if (read == -1) break
                        lastActivity.set(System.currentTimeMillis())
                        if (intensity > 60 && ThreadLocalRandom.current().nextInt(100) < 3) {
                            TcpTransportManager.applyWindowPulse(finalRemoteSocket)
                        }
                        writeMutex.lock()
                        try {
                            finalRemoteOut.write(buffer, 0, read)
                            finalRemoteOut.flush()
                        } finally {
                            writeMutex.unlock()
                        }
                        totalWrittenClient.addAndGet(read.toLong())
                        ProxyStats.recordStats(sessionId, read.toLong(), 0)
                    }
                } catch (e: Throwable) {
                    Log.v("TcpTransport", "Client to remote pump failed: ${e.message}")
                } finally {
                    remoteToClientJob.cancel()
                }
            }
        } catch (e: Throwable) {
            Log.e("TcpTransport", "Fatal session error for $targetHost: ${e.message}", e)
            onConnectFailure?.invoke(e.message ?: "UNKNOWN")
        } finally {
            try { clientSocket.close() } catch (e: Throwable) {}
            try { remoteSocket?.close() } catch (e: Throwable) {}
            ProxyStats.unregisterFlow(sessionId, true)
            ProxyStats.closeFlow(sessionId)
        }
    }
}
