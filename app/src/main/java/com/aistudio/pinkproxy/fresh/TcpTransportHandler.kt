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
        var sessionSuccess = false
        try {
            TcpTransportManager.configureSocket(clientSocket)

            if (RecoveryManager.isHostBlacklisted(targetHost)) {
                Log.w("TcpTransport", "Rejecting connection to blacklisted host: $targetHost")
                onConnectFailure?.invoke("BLACKLISTED")
                clientSocket.close()
                return
            }

            val resolved = RobustResolver.resolveDual(targetHost, vpnService)
            if (resolved.isEmpty()) {
                Log.w("TcpTransport", "Resolution failed for $targetHost")
                onConnectFailure?.invoke("DNS_FAILED")
                clientSocket.close()
                return
            }
            ProxyStats.addTraffic(targetHost)
            val requestedStrategy = forcedStrategy ?: BypassConfig.getBestStrategyForHost(targetHost)
            val config = BypassConfig.getSessionConfig(targetHost, requestedStrategy, BypassConfig.currentRttMs.value, TransportType.TCP)
            val effectiveStrategy = config.strategy
            val reasoning = DpiStrategySelector.getSelectionReasoning(effectiveStrategy, targetHost)
            ProxyStats.registerFlow(sessionId, targetHost, "TCP", effectiveStrategy, reasoning)
            VpnRuntimeState.updateStrategy(effectiveStrategy.name, reasoning)
            
            val totalWrittenClient = AtomicLong(0)
            val isTls = targetPort == 443 || targetPort == 8443

            val censorship = BypassConfig.censorshipLevel

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
            val firstClientPacketLen = accumulateInitialPacket(clientSocket, clientIn, firstClientPacket, transportBufferSize, 3000)

            var firstResponseData: ByteArray? = null
            var firstResponseLen = 0

            if (firstClientPacketLen <= 0) {
                // If we can't read anything initially, it might be a server-first protocol or just slow client.
                remoteSocket = TcpTransportManager.connectToBestIp(resolved, targetPort, vpnService, config, targetHost)
            } else {
                // Check if host has high failures or in panic mode - use multi-strategy race
                val useRace = censorship > 40 || DpiEngine.isBlacklisted(effectiveStrategy, targetHost) || (ProxyStats.censorshipIntensity.value > 50)
                
                if (useRace) {
                    val fallback = BypassConfig.getFallbackStrategy(effectiveStrategy)
                    val raceResult = TcpRaceConnector.racingConnect(
                        resolved, targetPort, vpnService, targetHost, 
                        effectiveStrategy, fallback,
                        firstClientPacket, firstClientPacketLen, transportBufferSize
                    )
                    
                    if (raceResult != null) {
                        remoteSocket = raceResult.socket
                        remoteIn = raceResult.input
                        remoteOut = raceResult.output
                        firstResponseData = raceResult.firstResponse
                        firstResponseLen = raceResult.firstResponseLen
                    }
                }

                // If not racing or race didn't connect, perform single-connect with Fast-Rescue Fallthrough
                if (remoteSocket == null) {
                    val attemptRes = connectAndSendWithRescue(
                        resolved = resolved,
                        port = targetPort,
                        vpnService = vpnService,
                        targetHost = targetHost,
                        primaryStrategy = effectiveStrategy,
                        firstPacket = firstClientPacket,
                        packetLen = firstClientPacketLen,
                        bufferSize = transportBufferSize
                    )
                    if (attemptRes != null) {
                        remoteSocket = attemptRes.socket
                        remoteIn = attemptRes.input
                        remoteOut = attemptRes.output
                        firstResponseData = attemptRes.firstResponse
                        firstResponseLen = attemptRes.firstResponseLen
                    }
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

            if (firstResponseData != null && firstResponseLen > 0) {
                clientOut.write(firstResponseData, 0, firstResponseLen)
                clientOut.flush()
                ProxyStats.recordStats(sessionId, 0, firstResponseLen.toLong())
            }

            onConnectSuccess?.invoke()
            sessionSuccess = true

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
                            } catch (e: java.net.SocketException) {
                                Log.v("TcpTransport", "Idle pulse SocketException: ${e.message}")
                            } catch (e: Exception) {
                                Log.v("TcpTransport", "Idle pulse failed: ${e.message}")
                            } finally {
                                writeMutex.unlock()
                            }
                        }
                    }
                }

                // Data pump jobs with BufferPool for Zero-Allocation streaming
                val isStreaming = HostClassifier.classify(targetHost) == HostCategory.STREAMING
                val remoteToClientJob = launch {
                    val buffer = if (isStreaming) BufferPool.obtain() else BufferPoolManager.obtain16k()
                    try {
                        while (isActive) {
                            val read = finalRemoteIn.read(buffer)
                            if (read == -1) {
                                // Graceful Half-Close: propagate EOF to client
                                try {
                                    if (!clientSocket.isClosed && !clientSocket.isOutputShutdown) {
                                        clientSocket.shutdownOutput()
                                    }
                                } catch (ignored: Throwable) {}
                                break
                            }
                            lastActivity.set(System.currentTimeMillis())
                            if (intensity > 70 && ThreadLocalRandom.current().nextInt(100) < 5) {
                                TcpTransportManager.oscillateWindowSize(clientSocket)
                            }
                            clientOut.write(buffer, 0, read)
                            clientOut.flush()
                            ProxyStats.recordStats(sessionId, 0, read.toLong())
                        }
                    } catch (e: java.net.SocketException) {
                        Log.v("TcpTransport", "Remote to client pump socket closed: ${e.message}")
                    } catch (e: java.io.IOException) {
                        Log.v("TcpTransport", "Remote to client pump IOException: ${e.message}")
                    } catch (e: Exception) {
                        Log.v("TcpTransport", "Remote to client pump error: ${e.message}")
                    } finally {
                        if (isStreaming) BufferPool.release(buffer) else BufferPoolManager.release16k(buffer)
                        try { clientSocket.close() } catch (e: java.io.IOException) {
                            Log.v("TcpTransport", "Failed to close client socket in pump: ${e.message}")
                        }
                    }
                }

                val clientBuffer = BufferPoolManager.obtain16k()
                try {
                    // Send remaining data & inspect subsequent packets in Keep-Alive connection
                    var packetIndex = 0
                    while (isActive) {
                        val read = clientIn.read(clientBuffer)
                        if (read == -1) {
                            // Graceful Half-Close: client has finished sending
                            try {
                                if (!finalRemoteSocket.isClosed && !finalRemoteSocket.isOutputShutdown) {
                                    finalRemoteSocket.shutdownOutput()
                                }
                            } catch (ignored: Throwable) {}
                            break
                        }
                        lastActivity.set(System.currentTimeMillis())
                        packetIndex++

                        if (intensity > 60 && ThreadLocalRandom.current().nextInt(100) < 3) {
                            TcpTransportManager.applyWindowPulse(finalRemoteSocket)
                        }

                        // Inspect secondary payloads on Keep-Alive / Multiplexed streams
                        val isSecondaryTlsOrHttp = packetIndex > 1 && (BypassApplier.isProbableTls(clientBuffer, read) || BypassApplier.isProbableHttp(clientBuffer, read))
                        
                        writeMutex.lock()
                        try {
                            if (isSecondaryTlsOrHttp && effectiveStrategy != BypassStrategy.DIRECT) {
                                Log.v("TcpTransport", "Detected secondary TLS/HTTP payload in packet #$packetIndex for $targetHost - applying evasion")
                                BypassApplier.applyBypass(finalRemoteSocket, finalRemoteOut, clientBuffer, read, config, targetHost)
                            } else {
                                finalRemoteOut.write(clientBuffer, 0, read)
                                finalRemoteOut.flush()
                            }
                        } finally {
                            writeMutex.unlock()
                        }
                        totalWrittenClient.addAndGet(read.toLong())
                        ProxyStats.recordStats(sessionId, read.toLong(), 0)
                    }
                } catch (e: java.net.SocketException) {
                    Log.v("TcpTransport", "Client to remote pump socket closed: ${e.message}")
                } catch (e: java.io.IOException) {
                    Log.v("TcpTransport", "Client to remote pump IOException: ${e.message}")
                } catch (e: Exception) {
                    Log.v("TcpTransport", "Client to remote pump error: ${e.message}")
                } finally {
                    BufferPoolManager.release16k(clientBuffer)
                    remoteToClientJob.cancel()
                }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: java.net.ConnectException) {
            Log.e("TcpTransport", "Connection refused to $targetHost: ${e.message}")
            onConnectFailure?.invoke("CONNECTION_REFUSED")
        } catch (e: java.net.SocketTimeoutException) {
            Log.e("TcpTransport", "Connection timed out for $targetHost")
            onConnectFailure?.invoke("TIMEOUT")
        } catch (e: java.io.IOException) {
            Log.e("TcpTransport", "IO error for $targetHost: ${e.message}")
            onConnectFailure?.invoke("IO_ERROR")
        } catch (e: Exception) {
            Log.e("TcpTransport", "Unexpected session error for $targetHost: ${e.message}", e)
            onConnectFailure?.invoke(e.message ?: "UNKNOWN")
        } catch (e: Throwable) {
            Log.e("TcpTransport", "Critical session error for $targetHost", e)
        } finally {
            try { clientSocket.close() } catch (e: java.io.IOException) {
                Log.v("TcpTransport", "Failed to close client socket: ${e.message}")
            }
            try { remoteSocket?.close() } catch (e: java.io.IOException) {
                Log.v("TcpTransport", "Failed to close remote socket: ${e.message}")
            }
            ProxyStats.unregisterFlow(sessionId, sessionSuccess)
            ProxyStats.closeFlow(sessionId)
        }
    }

    private fun accumulateInitialPacket(
        clientSocket: Socket,
        clientIn: InputStream,
        buffer: ByteArray,
        maxBufferSize: Int,
        timeoutMs: Int = 3000
    ): Int {
        clientSocket.soTimeout = timeoutMs
        var totalRead = 0
        try {
            val first = clientIn.read(buffer, 0, buffer.size)
            if (first <= 0) return 0
            totalRead = first

            // If payload is TLS Record Layer (0x16 0x03 0x00..0x04)
            if (totalRead >= 5 && buffer[0] == 0x16.toByte() && (buffer[1].toInt() and 0xFF) == 3) {
                val recordPayloadLen = ((buffer[3].toInt() and 0xFF) shl 8) or (buffer[4].toInt() and 0xFF)
                val targetLen = minOf(5 + recordPayloadLen, maxBufferSize, 512.coerceAtLeast(5 + recordPayloadLen))

                val startTime = System.currentTimeMillis()
                clientSocket.soTimeout = 150
                while (totalRead < targetLen && (System.currentTimeMillis() - startTime) < 500) {
                    try {
                        val read = clientIn.read(buffer, totalRead, targetLen - totalRead)
                        if (read <= 0) break
                        totalRead += read
                    } catch (e: java.net.SocketTimeoutException) {
                        break
                    }
                }
            } else if (totalRead < 512) {
                // General protocol accumulator: try to accumulate up to 512 bytes
                val startTime = System.currentTimeMillis()
                clientSocket.soTimeout = 100
                while (totalRead < 512 && (System.currentTimeMillis() - startTime) < 250) {
                    try {
                        val read = clientIn.read(buffer, totalRead, 512 - totalRead)
                        if (read <= 0) break
                        totalRead += read
                    } catch (e: java.net.SocketTimeoutException) {
                        break
                    }
                }
            }
        } catch (e: java.net.SocketTimeoutException) {
            Log.v("TcpTransport", "Initial client read timed out (normal for some protocols)")
        } catch (e: java.io.IOException) {
            Log.v("TcpTransport", "Initial client read failed: ${e.message}")
        }
        return totalRead
    }

    private data class RescueAttemptResult(
        val socket: Socket,
        val input: InputStream,
        val output: OutputStream,
        val firstResponse: ByteArray,
        val firstResponseLen: Int,
        val usedStrategy: BypassStrategy
    )

    private suspend fun connectAndSendWithRescue(
        resolved: List<java.net.InetAddress>,
        port: Int,
        vpnService: VpnService?,
        targetHost: String,
        primaryStrategy: BypassStrategy,
        firstPacket: ByteArray,
        packetLen: Int,
        bufferSize: Int
    ): RescueAttemptResult? {
        val attempts = mutableListOf<BypassStrategy>()
        attempts.add(primaryStrategy)
        
        val fallback1 = BypassConfig.getFallbackStrategy(primaryStrategy)
        if (!attempts.contains(fallback1)) {
            attempts.add(fallback1)
        }
        val diverseFallback = DpiStrategySelector.getDiverseFallback(primaryStrategy, HostClassifier.classify(targetHost), TransportType.TCP)
        if (!attempts.contains(diverseFallback)) {
            attempts.add(diverseFallback)
        }

        val rtt = BypassConfig.currentRttMs.value
        // Silent drop detection threshold: 750ms + 1.5 * RTT (capped at 1600ms)
        val watchdogTimeoutMs = (750 + (rtt * 1.5).toInt()).coerceIn(600, 1600)

        for ((index, strategy) in attempts.take(3).withIndex()) {
            val config = BypassConfig.getSessionConfig(targetHost, strategy, rtt, TransportType.TCP)
            val rs = TcpTransportManager.connectToBestIp(resolved, port, vpnService, config, targetHost) ?: continue

            try {
                rs.tcpNoDelay = true
                rs.soTimeout = watchdogTimeoutMs
                val rsOut = rs.getOutputStream()
                val rsIn = rs.getInputStream()

                val startTime = System.currentTimeMillis()
                BypassApplier.applyBypass(rs, rsOut, firstPacket, packetLen, config, targetHost)

                val responseBuf = ByteArray(bufferSize)
                val readBytes = withTimeoutOrNull(watchdogTimeoutMs.toLong()) {
                    try {
                        rsIn.read(responseBuf)
                    } catch (e: Exception) {
                        -1
                    }
                } ?: -1

                if (readBytes > 0) {
                    val latency = System.currentTimeMillis() - startTime
                    val quality = if (BypassApplier.isProbableTls(responseBuf, readBytes) || BypassApplier.isProbableHttp(responseBuf, readBytes)) {
                        ObservationQuality.HANDSHAKE_COMPLETE
                    } else {
                        ObservationQuality.TLS_RECORD_RECEIVED
                    }
                    DpiEngine.recordStrategyResult(targetHost, strategy, true, latency, quality = quality)
                    if (index > 0) {
                        ProxyStats.logRecovery("Fast rescue successful for $targetHost using $strategy (attempt #${index + 1})")
                    }
                    return RescueAttemptResult(rs, rsIn, rsOut, responseBuf, readBytes, strategy)
                } else {
                    // Silent drop or RST detected by TSPU
                    DpiEngine.recordStrategyResult(targetHost, strategy, false, 0, reason = FailureReason.CENSORSHIP_STALL)
                    Log.w("TcpTransport", "Watchdog triggered for $targetHost with $strategy (attempt #${index + 1}). Fast failover to next strategy.")
                    try { rs.close() } catch (e: Exception) {}
                }
            } catch (e: Exception) {
                val reason = if (e.message?.contains("reset", ignoreCase = true) == true || e.message?.contains("broken pipe", ignoreCase = true) == true) {
                    FailureReason.TCP_RESET
                } else {
                    FailureReason.TIMEOUT
                }
                DpiEngine.recordStrategyResult(targetHost, strategy, false, 0, reason = reason)
                Log.w("TcpTransport", "Connection error on strategy $strategy for $targetHost: ${e.message}. Rescuing with fallback.")
                try { rs.close() } catch (ex: Exception) {}
            }
        }
        return null
    }
}
