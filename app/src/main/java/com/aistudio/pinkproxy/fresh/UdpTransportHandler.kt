package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap

object UdpTransportHandler {

    suspend fun handleUdpAssociate(
        clientSocket: Socket,
        output: java.io.OutputStream,
        vpnService: VpnService,
        scope: CoroutineScope
    ) = kotlinx.coroutines.coroutineScope {
        val socksSessionId = java.util.UUID.randomUUID().toString()
        val udpSocket = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val localPort = udpSocket.localPort
        
        try {
            val resp = ByteArray(10)
            resp[0] = 5; resp[1] = 0; resp[2] = 0; resp[3] = 1
            resp[4] = 127; resp[5] = 0; resp[6] = 0; resp[7] = 1
            resp[8] = (localPort shr 8).toByte()
            resp[9] = localPort.toByte()
            output.write(resp)
            output.flush()

            coroutineScope {
                launch(ProxyDispatcher.udpRelay) {
                    val buffer = ByteArray(65535)
                    while (isActive) {
                        try {
                            val packet = DatagramPacket(buffer, buffer.size)
                            udpSocket.receive(packet)

                            val clientAddr = packet.address
                            val clientPort = packet.port
                            val data = packet.data
                            val offset = packet.offset
                            val len = packet.length

                            if (len < 4) continue
                            val frag = data[offset + 2].toInt()
                            if (frag != 0) continue

                            val atyp = data[offset + 3].toInt()
                            var headerLen = 0
                            var host = ""
                            var port = 0

                            if (atyp == 1) { // IPv4
                                headerLen = 4 + 4 + 2
                                if (len < headerLen) continue
                                val ipBytes = data.copyOfRange(offset + 4, offset + 8)
                                host = InetAddress.getByAddress(ipBytes).hostAddress ?: ""
                                port = ((data[offset + 8].toInt() and 0xFF) shl 8) or (data[offset + 9].toInt() and 0xFF)
                            } else if (atyp == 3) { // Domain
                                if (len < 5) continue
                                val domainLen = data[offset + 4].toInt() and 0xFF
                                headerLen = 4 + 1 + domainLen + 2
                                if (len < headerLen) continue
                                host = String(data, offset + 5, domainLen)
                                port = ((data[offset + 5 + domainLen].toInt() and 0xFF) shl 8) or (data[offset + 6 + domainLen].toInt() and 0xFF)
                            } else if (atyp == 4) { // IPv6
                                headerLen = 4 + 16 + 2
                                if (len < headerLen) continue
                                val ipBytes = data.copyOfRange(offset + 4, offset + 20)
                                host = InetAddress.getByAddress(ipBytes).hostAddress ?: ""
                                port = ((data[offset + 20].toInt() and 0xFF) shl 8) or (data[offset + 21].toInt() and 0xFF)
                            }

                            if (headerLen > 0 && len > headerLen) {
                                val payload = data.copyOfRange(offset + headerLen, offset + len)
                                val sessionKey = UdpSessionKey(clientAddr, clientPort, host, port)

                                if (shouldBlockQuicForHost(host, port, payload)) {
                                    Log.d("UdpTransport", "QUIC packet blocked for $host:$port to force TCP fallback")
                                    continue
                                }
                                
                                val udpStrat = DpiStrategySelector.getBestStrategy(HostClassifier.classify(host), host, TransportType.UDP)
                                var association = UdpAssociationTable.getSession(sessionKey)

                                if (association == null || association.outSocket == null) {
                                    var targetInet: InetAddress? = null
                                    val isIp = host.matches(Regex("^\\d+\\.\\d+\\.\\d+\\.\\d+$")) || host.contains(":")
                                    if (isIp) {
                                        targetInet = InetAddress.getByName(host)
                                    } else {
                                        val resolved = RobustResolver.resolveDual(host, vpnService)
                                        if (resolved.isNotEmpty()) {
                                            targetInet = resolved.random()
                                        }
                                    }
                                    
                                    if (targetInet == null) {
                                        Log.w("UdpTransport", "Failed to resolve $host")
                                        continue
                                    }
                                    
                                    association = UdpAssociationTable.getOrCreateSession(socksSessionId, clientAddr, clientPort, host, port, udpStrat)
                                    val outSocket = UdpTransportManager.createProtectedSocket(vpnService)
                                    association.outSocket = outSocket
                                    association.targetInet = targetInet
                                    
                                    val readerJob = launch(ProxyDispatcher.udpRelay) {
                                        val inBuffer = ByteArray(65535)
                                        while (isActive) {
                                            try {
                                                val inPacket = DatagramPacket(inBuffer, inBuffer.size)
                                                outSocket.receive(inPacket)
                                                
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
                                                
                                                udpSocket.send(DatagramPacket(fullResp, fullResp.size, sessionKey.clientAddress, sessionKey.clientPort))
                                                ProxyStats.recordStats("udp_inbound", 0, inPacket.length.toLong())
                                                
                                                UdpAssociationTable.touchSession(sessionKey, receivedBytes = inPacket.length.toLong())
                                                
                                                val matchedProbe = association.popProbe()
                                                if (matchedProbe != null) {
                                                    val latency = (System.currentTimeMillis() - matchedProbe.sentTime).coerceAtLeast(1L)
                                                    DpiStrategySelector.recordResult(
                                                        strategy = matchedProbe.strategy,
                                                        success = true,
                                                        transport = TransportType.UDP,
                                                        latencyMs = latency,
                                                        host = matchedProbe.host,
                                                        quality = ObservationQuality.APPLICATION_DATA_EXCHANGED,
                                                        requestedStrategy = matchedProbe.strategy,
                                                        effectiveStrategy = matchedProbe.strategy
                                                    )
                                                }
                                            } catch (e: Exception) {
                                                if (e !is CancellationException) Log.v("UdpTransport", "Inbound UDP error for $sessionKey: ${e.message}")
                                                break 
                                            }
                                        }
                                    }
                                    association.readerJob = readerJob
                                }
                                
                                if (udpStrat != BypassStrategy.DIRECT && udpStrat.implementationStatus != ImplementationStatus.UNSUPPORTED && udpStrat.implementationStatus != ImplementationStatus.SIMULATED) {
                                    association.addProbe(UdpPendingProbe(host, udpStrat, System.currentTimeMillis()))
                                    
                                    launch(ProxyDispatcher.udpRelay) {
                                        try {
                                            UdpAssociationTable.touchSession(sessionKey, sentBytes = payload.size.toLong())
                                            val config = BypassConfig.getSessionConfig(host, udpStrat, 50, TransportType.UDP)
                                            val outPacket = DatagramPacket(payload, payload.size, association.targetInet, port)
                                            BypassApplier.applyUdpBypass(association.outSocket!!, outPacket, config, host)
                                            ProxyStats.recordStats("udp_outbound", 0, payload.size.toLong())
                                        } catch (e: Exception) {
                                            if (e !is CancellationException) Log.v("UdpTransport", "UDP Strategy execution failed: ${e.message}")
                                            association.popProbe()
                                            if (e !is TransportException && e !is DnsException && e !is java.net.UnknownHostException) {
                                                DpiStrategySelector.recordResult(
                                                    strategy = udpStrat,
                                                    success = false,
                                                    transport = TransportType.UDP,
                                                    latencyMs = 5000L,
                                                    host = host,
                                                    quality = ObservationQuality.CONNECT_ONLY,
                                                    requestedStrategy = udpStrat,
                                                    effectiveStrategy = udpStrat
                                                )
                                            }
                                        }
                                    }
                                } else {
                                    UdpAssociationTable.touchSession(sessionKey, sentBytes = payload.size.toLong())
                                    association.outSocket?.send(DatagramPacket(payload, payload.size, association.targetInet, port))
                                    ProxyStats.recordStats("udp_outbound", 0, payload.size.toLong())
                                }
                            }
                        } catch (e: Exception) {
                            if (e !is CancellationException) Log.v("UdpTransport", "UDP Receive loop error: ${e.message}")
                        }
                    }
                }

                // Wait until client TCP control connection closes
                launch(ProxyDispatcher.io) {
                    try {
                        val input = clientSocket.getInputStream()
                        while (input.read() != -1) { /* Just wait */ }
                    } catch (e: Exception) {
                        if (e !is CancellationException) Log.v("UdpTransport", "Client control connection closed: ${e.message}")
                    } finally {
                        this@coroutineScope.cancel()
                    }
                }
            }
        } finally {
            try { udpSocket.close() } catch(e:Exception){}
            UdpAssociationTable.removeSessionsForSocksSession(socksSessionId)
            try { clientSocket.close() } catch (e: Exception) {}
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
