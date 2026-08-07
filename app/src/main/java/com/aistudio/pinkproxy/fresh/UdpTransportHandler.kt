package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.Collections

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
            
            var clientUdpAddress: InetAddress? = null
            var clientUdpPort = 0
            
            val activeSessions = ConcurrentHashMap<String, Long>()
            val udpOutChannels = Array(8) { kotlinx.coroutines.channels.Channel<Pair<DatagramPacket, String>>(500) }
            
            coroutineScope {
                val jobs = mutableListOf<Job>()
                
                repeat(8) { i ->
                    val outSocket = outSockets[i]
                    jobs += launch(ProxyDispatcher.io) {
                        launch {
                            val rnd = ThreadLocalRandom.current()
                            try {
                                while (isActive) {
                                    delay(rnd.nextLong(30000, 60000))
                                    val now = System.currentTimeMillis()
                                    activeSessions.entries.removeIf { entry ->
                                        if (now - entry.value > 90000) {
                                            ProxyStats.closeFlow("udp_${entry.key}")
                                            true
                                        } else {
                                            false
                                        }
                                    }
                                    
                                    for (session in activeSessions.keys) {
                                        val parts = session.split(":")
                                        if (parts.size == 2) {
                                            UdpTransportManager.sendUdpHeartbeat(outSocket, parts[0], parts[1].toInt())
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

                        for (work in udpOutChannels[i]) {
                            try {
                                outSocket.send(work.first)
                                activeSessions[work.second] = System.currentTimeMillis()
                            } catch (e: java.net.SocketException) {
                                Log.v("UdpTransport", "Outbound SocketException: ${e.message}")
                            } catch (e: java.io.IOException) {
                                Log.v("UdpTransport", "Outbound IOException: ${e.message}")
                            } catch (e: Exception) {
                                Log.v("UdpTransport", "Outbound send failed: ${e.message}")
                            }
                        }
                    }
                }

                jobs += launch(ProxyDispatcher.io) {
                    val buffer = ByteArray(4096)
                    while (isActive) {
                        try {
                            val packet = DatagramPacket(buffer, buffer.size)
                            udpSocket.receive(packet)
                            
                            if (clientUdpAddress == null) {
                                clientUdpAddress = packet.address
                                clientUdpPort = packet.port
                            }
                            
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
                                if (!activeSessions.containsKey(sessionKey)) {
                                    ProxyStats.registerFlow("udp_$sessionKey", host, "UDP", BypassConfig.getBestStrategyForHost(host))
                                    activeSessions[sessionKey] = System.currentTimeMillis()
                                }
                                
                                val resolved = RobustResolver.resolve(host, vpnService)
                                if (resolved.isNotEmpty()) {
                                    val targetInet = resolved.random()
                                    val outPacket = DatagramPacket(payload, payload.size, targetInet, port)
                                    val workerIdx = (host.hashCode() and 0x7FFFFFFF) % 8
                                    
                                    val config = BypassConfig.getSessionConfig(host, BypassConfig.getBestStrategyForHost(host), BypassConfig.currentRttMs.value)
                                    // Use BypassApplier for all UDP evasion
                                    launch {
                                        try {
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
                    jobs += launch(ProxyDispatcher.io) {
                        val inBuffer = ByteArray(4096)
                        val inSocket = outSockets[i]
                        while (isActive) {
                            try {
                                val inPacket = DatagramPacket(inBuffer, inBuffer.size)
                                inSocket.receive(inPacket)
                                
                                val targetAddr = clientUdpAddress ?: continue
                                val targetPort = clientUdpPort
                                
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
        // Shared buffers cleanup if any
    }
}
