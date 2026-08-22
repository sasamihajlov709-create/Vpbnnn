package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ThreadLocalRandom

object UdpTransportHandler {

    suspend fun handleUdpAssociate(
        clientSocket: Socket,
        output: java.io.OutputStream,
        vpnService: VpnService,
        scope: CoroutineScope
    ) {
        val udpSocket = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val localPort = udpSocket.localPort
        
        val outSockets = Array(8) { UdpTransportManager.createProtectedSocket(vpnService) }
        
        try {
            val resp = ByteArray(10)
            resp[0] = 5; resp[1] = 0; resp[2] = 0; resp[3] = 1
            resp[4] = 127; resp[5] = 0; resp[6] = 0; resp[7] = 1
            resp[8] = (localPort shr 8).toByte()
            resp[9] = localPort.toByte()
            output.write(resp)
            output.flush()
            
            // Client association address & port pair mapping
            val clientEndpoints = ConcurrentHashMap<String, Pair<InetAddress, Int>>()
            data class UdpPendingProbe(val host: String, val strategy: BypassStrategy, val sentTime: Long)
            val pendingUdpProbes = ConcurrentHashMap<String, UdpPendingProbe>()
            
            coroutineScope {
                val jobs = mutableListOf<Job>()
                
                // Cleanup and timeout inspector for UDP flows
                jobs += launch(ProxyDispatcher.scheduler) {
                    while (isActive) {
                        delay(10000)
                        val now = System.currentTimeMillis()
                        
                        // Age out unacknowledged UDP packets (> 3500ms) and score degraded observation
                        pendingUdpProbes.entries.removeIf { (endpoint, probe) ->
                            if (now - probe.sentTime > 3500) {
                                DpiStrategySelector.recordResult(
                                    host = probe.host,
                                    strategy = probe.strategy,
                                    success = false,
                                    latencyMs = 0,
                                    reason = FailureReason.TIMEOUT,
                                    quality = ObservationQuality.CONNECT_ONLY,
                                    requestedStrategy = probe.strategy,
                                    effectiveStrategy = probe.strategy,
                                    transport = TransportType.UDP
                                )
                                true
                            } else {
                                false
                            }
                        }

                        // Age out idle sessions in association table
                        UdpAssociationTable.cleanupExpiredSessions()
                    }
                }
                
                repeat(8) { i ->
                    val outSocket = outSockets[i]
                    jobs += launch(ProxyDispatcher.scheduler) {
                        val rnd = ThreadLocalRandom.current()
                        try {
                            while (isActive) {
                                delay(rnd.nextLong(30000, 60000))
                                for ((sessionKey, _) in clientEndpoints) {
                                    val lastColon = sessionKey.lastIndexOf(':')
                                    if (lastColon > 0 && lastColon < sessionKey.length - 1) {
                                        val rawHost = sessionKey.substring(0, lastColon).removePrefix("[").removeSuffix("]")
                                        val portInt = sessionKey.substring(lastColon + 1).toIntOrNull()
                                        if (rawHost.isNotEmpty() && portInt != null) {
                                            UdpTransportManager.sendUdpHeartbeat(outSocket, rawHost, portInt)
                                        }
                                    }
                                }
                            }
                        } catch (e: CancellationException) {
                            // Normal
                        } catch (e: java.net.SocketException) {
                            Log.v("UdpTransport", "HB SocketException: ${e.message}")
                        } catch (e: java.io.IOException) {
                            Log.v("UdpTransport", "HB IOException: ${e.message}")
                        } catch (e: Exception) {
                            Log.v("UdpTransport", "HB error: ${e.message}")
                        }
                    }
                }

                jobs += launch(ProxyDispatcher.udpRelay) {
                    val buffer = ByteArray(4096)
                    while (isActive) {
                        try {
                            val packet = DatagramPacket(buffer, buffer.size)
                            udpSocket.receive(packet)
                            
                            val clientAddr = packet.address
                            val clientPort = packet.port
                            val clientPairKey = "${clientAddr.hostAddress}:$clientPort"
                            
                            val data = packet.data
                            val offset = packet.offset
                            val len = packet.length
                            
                            if (len < 10) continue
                            // SOCKS5 UDP header: RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT
                            val atyp = data[offset + 3].toInt()
                            var headerLen = 0
                            var host = ""
                            var port = 0
                            
                            when (atyp) {
                                1 -> { // IPv4
                                    host = "${data[offset+4].toInt() and 0xFF}.${data[offset+5].toInt() and 0xFF}.${data[offset+6].toInt() and 0xFF}.${data[offset+7].toInt() and 0xFF}"
                                    port = ((data[offset+8].toInt() and 0xFF) shl 8) or (data[offset+9].toInt() and 0xFF)
                                    headerLen = 10
                                }
                                3 -> { // Domain
                                    val domainLen = data[offset+4].toInt() and 0xFF
                                    host = String(data, offset+5, domainLen, Charsets.US_ASCII)
                                    port = ((data[offset+5+domainLen].toInt() and 0xFF) shl 8) or (data[offset+6+domainLen].toInt() and 0xFF)
                                    headerLen = 7 + domainLen
                                }
                                4 -> { // IPv6
                                    val addrBytes = ByteArray(16)
                                    System.arraycopy(data, offset + 4, addrBytes, 0, 16)
                                    host = try {
                                        val addr = InetAddress.getByAddress(addrBytes)
                                        if (addr.hostAddress?.contains(":") == true) "[${addr.hostAddress}]" else addr.hostAddress ?: ""
                                    } catch (e: Exception) {
                                        "ipv6_error"
                                    }
                                    port = ((data[offset + 20].toInt() and 0xFF) shl 8) or (data[offset + 21].toInt() and 0xFF)
                                    headerLen = 22
                                }
                            }
                            
                            if (headerLen > 0 && len > headerLen) {
                                val payload = data.copyOfRange(offset + headerLen, offset + len)
                                val sessionKey = "$host:$port"
                                
                                clientEndpoints[sessionKey] = Pair(clientAddr, clientPort)

                                if (shouldBlockQuicForHost(host, port, payload)) {
                                    Log.d("UdpTransport", "QUIC packet blocked for $host:$port to force TCP fallback")
                                    continue
                                }

                                val udpStrat = BypassConfig.getBestStrategyForHost(host, TransportType.UDP)
                                val sessionEntry = UdpAssociationTable.getOrCreateSession(
                                    clientAddress = clientAddr,
                                    clientPort = clientPort,
                                    destinationHost = host,
                                    destinationPort = port,
                                    strategy = udpStrat
                                )

                                val reasoning = DpiStrategySelector.getSelectionReasoning(udpStrat, host)
                                ProxyStats.registerFlow("udp_$sessionKey", host, "UDP", udpStrat, reasoning)
                                VpnRuntimeState.updateStrategy(udpStrat.name, reasoning)
                                
                                val resolved = RobustResolver.resolveDual(host, vpnService)
                                if (resolved.isNotEmpty()) {
                                    val targetInet = resolved.random()
                                    val outPacket = DatagramPacket(payload, payload.size, targetInet, port)
                                    val workerIdx = (host.hashCode() and 0x7FFFFFFF) % 8
                                    
                                    val config = BypassConfig.getSessionConfig(host, udpStrat, BypassConfig.currentRttMs.value, TransportType.UDP)
                                    
                                    val endpointKey = "${targetInet.hostAddress}:$port"
                                    pendingUdpProbes[endpointKey] = UdpPendingProbe(host, udpStrat, System.currentTimeMillis())
                                    UdpAssociationTable.bindEndpoint(endpointKey, sessionEntry.key)

                                    // Use BypassApplier for all UDP evasion
                                    launch(ProxyDispatcher.udpRelay) {
                                        try {
                                            UdpAssociationTable.touchSession(sessionEntry.key, sentBytes = payload.size.toLong())
                                            ProxyStats.recordStats("udp_$sessionKey", payload.size.toLong(), 0)
                                            ProxyStats.addTraffic(host)
                                            BypassApplier.applyUdpBypass(outSockets[workerIdx], outPacket, config, host)
                                        } catch (e: java.io.IOException) {
                                            Log.v("UdpTransport", "UDP Bypass IOException: ${e.message}")
                                        } catch (e: Exception) {
                                            Log.v("UdpTransport", "UDP Bypass apply failed: ${e.message}")
                                        }
                                    }
                                }
                            }
                        } catch (e: java.net.SocketException) {
                            if (e !is CancellationException) Log.v("UdpTransport", "UDP Receive loop SocketException: ${e.message}")
                        } catch (e: java.io.IOException) {
                            Log.v("UdpTransport", "UDP Receive loop IOException: ${e.message}")
                        } catch (e: Exception) {
                            if (e !is CancellationException) Log.v("UdpTransport", "UDP Receive loop error: ${e.message}")
                        }
                    }
                }

                // Inbound return loop (Remote -> Local UDP -> Client)
                repeat(8) { i ->
                    jobs += launch(ProxyDispatcher.udpRelay) {
                        val inBuffer = ByteArray(4096)
                        val inSocket = outSockets[i]
                        while (isActive) {
                            try {
                                val inPacket = DatagramPacket(inBuffer, inBuffer.size)
                                inSocket.receive(inPacket)
                                
                                val endpointKey = "${inPacket.address.hostAddress}:${inPacket.port}"
                                val sessionKey = UdpAssociationTable.findClientForKey(endpointKey)
                                
                                val (targetAddr, targetPort) = if (sessionKey != null) {
                                    Pair(sessionKey.clientAddress, sessionKey.clientPort)
                                } else {
                                    // Fallback to latest registered client endpoint
                                    clientEndpoints.values.firstOrNull() ?: continue
                                }
                                
                                // Re-wrap into SOCKS5 UDP response
                                val remoteAddr = inPacket.address.address
                                val remotePort = inPacket.port
                                val socksHeader = if (remoteAddr.size == 4) {
                                    val h = ByteArray(10)
                                    h[0]=0; h[1]=0; h[2]=0; h[3]=1
                                    System.arraycopy(remoteAddr, 0, h, 4, 4)
                                    h[8] = (remotePort shr 8).toByte()
                                    h[9] = remotePort.toByte()
                                    h
                                } else if (remoteAddr.size == 16) {
                                    val h = ByteArray(22)
                                    h[0]=0; h[1]=0; h[2]=0; h[3]=4
                                    System.arraycopy(remoteAddr, 0, h, 4, 16)
                                    h[20] = (remotePort shr 8).toByte()
                                    h[21] = remotePort.toByte()
                                    h
                                } else continue
                                
                                val fullResp = ByteArray(socksHeader.size + inPacket.length)
                                System.arraycopy(socksHeader, 0, fullResp, 0, socksHeader.size)
                                System.arraycopy(inPacket.data, inPacket.offset, fullResp, socksHeader.size, inPacket.length)
                                
                                udpSocket.send(DatagramPacket(fullResp, fullResp.size, targetAddr, targetPort))
                                ProxyStats.recordStats("udp_inbound", 0, inPacket.length.toLong())
                                
                                if (sessionKey != null) {
                                    UdpAssociationTable.touchSession(sessionKey, receivedBytes = inPacket.length.toLong())
                                }

                                val matchedProbe = pendingUdpProbes.remove(endpointKey)
                                if (matchedProbe != null) {
                                    val latency = (System.currentTimeMillis() - matchedProbe.sentTime).coerceAtLeast(1L)
                                    DpiStrategySelector.recordResult(
                                        host = matchedProbe.host,
                                        strategy = matchedProbe.strategy,
                                        success = true,
                                        latencyMs = latency,
                                        quality = ObservationQuality.APPLICATION_DATA_EXCHANGED,
                                        requestedStrategy = matchedProbe.strategy,
                                        effectiveStrategy = matchedProbe.strategy,
                                        transport = TransportType.UDP
                                    )
                                }
                            } catch (e: java.net.SocketException) {
                                if (e !is CancellationException) Log.v("UdpTransport", "Inbound UDP SocketException: ${e.message}")
                            } catch (e: java.io.IOException) {
                                Log.v("UdpTransport", "Inbound UDP IOException: ${e.message}")
                            } catch (e: Exception) {
                                if (e !is CancellationException) Log.v("UdpTransport", "Inbound UDP failed: ${e.message}")
                            }
                        }
                    }
                }

                // Wait until client TCP control connection closes
                launch(ProxyDispatcher.io) {
                    try {
                        val input = clientSocket.getInputStream()
                        while (input.read() != -1) { /* Just wait */ }
                    } catch (e: java.io.IOException) {
                        Log.v("UdpTransport", "Client control connection closed: ${e.message}")
                    } catch (e: Exception) {
                        Log.v("UdpTransport", "Client control connection error: ${e.message}")
                    } finally {
                        this@coroutineScope.cancel()
                    }
                }
            }
        } finally {
            udpSocket.close()
            outSockets.forEach { try { it.close() } catch (e: Exception) { Log.v("UdpTransport", "Failed to close outSocket: ${e.message}") } }
            try { clientSocket.close() } catch (e: Exception) { Log.v("UdpTransport", "Failed to close clientSocket: ${e.message}") }
        }
    }

    fun clearBuffers() {
        UdpAssociationTable.clear()
    }

    internal fun isStunPacket(payload: ByteArray): Boolean {
        if (payload.size < 20) return false
        val msgTypeHigh = payload[0].toInt() and 0xC0
        if (msgTypeHigh != 0) return false
        return payload[4] == 0x21.toByte() &&
               payload[5] == 0x12.toByte() &&
               payload[6] == 0xA4.toByte() &&
               payload[7] == 0x42.toByte()
    }

    internal fun shouldBlockQuicForHost(host: String, port: Int, payload: ByteArray): Boolean {
        // If voice STUN packet (Discord/Telegram voice sessions), NEVER block QUIC/UDP
        if (isStunPacket(payload)) return false

        val mode = BypassConfig.quicBypassMode.value
        if (mode == QuicBypassMode.FORCE_ALLOW) return false
        if (mode == QuicBypassMode.FORCE_BLOCK || BypassConfig.blockQuic) {
            return isQuicPacket(port, payload)
        }
        
        val category = HostClassifier.classify(host)
        if (category == HostCategory.MESSENGER || category == HostCategory.GAMING) {
            return false
        }

        // AUTO mode: For video streaming (YouTube CDN googlevideo, twitch) and heavy CDN endpoints,
        // Russian TSPU corrupts QUIC Initial packets causing 5-8s stream playback stalls.
        // Fast-blocking QUIC here allows the player to instantly (0ms) establish HTTP/1.1 or HTTP/2 over our accelerated TCP bypass engine.
        if (category == HostCategory.STREAMING || host.contains("googlevideo.com") || host.contains("ytimg.com")) {
            return true
        }

        return false
    }

    internal fun isQuicPacket(port: Int, payload: ByteArray): Boolean {
        if (port == 443 || port == 8443) return true
        if (payload.isEmpty()) return false
        val first = payload[0].toInt() and 0xFF
        return (first and 0x80) != 0 || (first and 0x40) != 0
    }
}
