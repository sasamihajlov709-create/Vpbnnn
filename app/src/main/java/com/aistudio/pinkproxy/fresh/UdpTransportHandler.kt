package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom

object UdpTransportHandler {

    suspend fun handleUdpAssociate(
        clientSocket: Socket,
        output: java.io.OutputStream,
        vpnService: VpnService,
        scope: CoroutineScope
    ) {
        // Open DatagramSocket to receive SOCKS5 UDP packets
        val udpSocket = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val localPort = udpSocket.localPort
        
        // One outgoing socket for the entire UDP associate session
        val outSocket = DatagramSocket()
        try { vpnService.protect(outSocket) } catch (e: Exception) {}

        // Send Success response with our UDP bound address
        val resp = ByteArray(10)
        resp[0] = 5; resp[1] = 0; resp[2] = 0; resp[3] = 1
        resp[4] = 127; resp[5] = 0; resp[6] = 0; resp[7] = 1
        resp[8] = (localPort shr 8).toByte()
        resp[9] = localPort.toByte()
        output.write(resp)
        output.flush()
        
        var clientUdpAddress: InetAddress? = null
        var clientUdpPort = 0
        
        val udpOutChannel = kotlinx.coroutines.channels.Channel<Pair<DatagramPacket, String>>(100)
        
        coroutineScope {
            val jobs = mutableListOf<Job>()
            
            // Outgoing UDP Workers
            repeat(6) {
                jobs += launch(Dispatchers.IO) {
                    try {
                        for (work in udpOutChannel) {
                            val (packet, targetHost) = work
                            // Use async launch for packets that might need delays/bypass strategies
                            // to avoid blocking the main UDP worker loop
                            launch {
                                try {
                                    sendUdpPacket(outSocket, packet, targetHost)
                                } catch (e: Exception) {
                                    Log.v("UdpTransport", "Send error: ${e.message}")
                                }
                            }
                        }
                    } catch (e: Exception) {
                        if (e !is CancellationException) Log.v("UdpTransport", "UDP Outbound worker error: ${e.message}")
                    }
                }
            }

            // Receive from Target, forward to SOCKS5 Client
            jobs += launch(Dispatchers.IO) {
                val buffer = ProxyStats.obtain64k()
                val respBuffer = ProxyStats.obtain64k()
                val packet = DatagramPacket(buffer, buffer.size)
                try {
                    while (isActive) {
                        packet.setData(buffer)
                        try {
                            outSocket.receive(packet)
                        } catch (e: java.net.SocketTimeoutException) {
                            continue
                        }

                        if (clientUdpAddress != null) {
                            val addrBytes = packet.address.address
                            var offset = 0
                            respBuffer[offset++] = 0; respBuffer[offset++] = 0; respBuffer[offset++] = 0
                            if (addrBytes.size == 4) { respBuffer[offset++] = 1 } else { respBuffer[offset++] = 4 }
                            System.arraycopy(addrBytes, 0, respBuffer, offset, addrBytes.size); offset += addrBytes.size
                            respBuffer[offset++] = (packet.port shr 8).toByte(); respBuffer[offset++] = (packet.port and 0xFF).toByte()
                            System.arraycopy(packet.data, packet.offset, respBuffer, offset, packet.length); offset += packet.length
                            udpSocket.send(DatagramPacket(respBuffer, offset, clientUdpAddress, clientUdpPort))
                            ProxyStats.updateBytes(packet.length.toLong())
                        }
                    }
                } catch (e: Exception) {
                    if (e !is CancellationException) Log.v("UdpTransport", "Target->Client error: ${e.message}")
                } finally {
                    ProxyStats.release64k(buffer)
                    ProxyStats.release64k(respBuffer)
                }
            }

            // Receive from SOCKS5 Client, forward to Target
            jobs += launch(Dispatchers.IO) {
                val buffer = ProxyStats.obtain64k()
                val packet = DatagramPacket(buffer, buffer.size)
                try {
                    while (isActive) {
                        packet.setData(buffer)
                        try {
                            udpSocket.receive(packet)
                        } catch (e: java.net.SocketTimeoutException) {
                            continue
                        }
                        clientUdpAddress = packet.address
                        clientUdpPort = packet.port
                        
                        val data = packet.data
                        val len = packet.length
                        if (len < 10) continue
                        
                        // Parse SOCKS5 UDP header
                        val frag = data[2].toInt()
                        if (frag != 0) continue 
                        
                        val pAtyp = data[3].toInt()
                        var headerLen = 4
                        var targetHost = ""
                        when (pAtyp) {
                            1 -> {
                                headerLen += 4
                                if (len < headerLen + 2) continue
                                targetHost = "${data[4].toInt() and 0xFF}.${data[5].toInt() and 0xFF}.${data[6].toInt() and 0xFF}.${data[7].toInt() and 0xFF}"
                            }
                            3 -> {
                                val dlen = data[4].toInt() and 0xFF
                                headerLen += 1 + dlen
                                if (len < headerLen + 2) continue
                                targetHost = String(data, 5, dlen, Charsets.US_ASCII)
                            }
                            4 -> {
                                headerLen += 16
                                if (len < headerLen + 2) continue
                                val ipBytes = data.copyOfRange(4, 20)
                                targetHost = InetAddress.getByAddress(ipBytes).hostAddress ?: ""
                            }
                            else -> continue
                        }
                        val targetPortNum = ((data[headerLen].toInt() and 0xFF) shl 8) or (data[headerLen + 1].toInt() and 0xFF)
                        headerLen += 2
                        
                        val payloadLen = len - headerLen
                        ProxyStats.updateBytes(payloadLen.toLong())
                        
                        if (targetPortNum == 53) {
                            val query = DnsUtils.parseDnsQName(data, headerLen, payloadLen)
                            if (query != null) {
                                val host = query.qname
                                val clientAddr = packet.address
                                val clientPort = packet.port
                                val cached = RobustResolver.getCached(host)
                                if (cached != null) {
                                    val ipStrs = cached.map { it.hostAddress ?: "" }.filter { it.isNotEmpty() }
                                    if (ipStrs.isNotEmpty()) {
                                        val dnsReply = DnsUtils.buildDnsReply(data, headerLen, payloadLen, ipStrs, query.qtype == 28)
                                        val headerSize = if (pAtyp == 1) 10 else if (pAtyp == 4) 22 else 7 + (data[4].toInt() and 0xFF)
                                        val responseBytes = ProxyStats.obtain8k()
                                        try {
                                            var off = 0
                                            responseBytes[off++] = 0; responseBytes[off++] = 0; responseBytes[off++] = 0; responseBytes[off++] = pAtyp.toByte()
                                            if (pAtyp == 1) { System.arraycopy(data, 4, responseBytes, off, 4); off += 4 }
                                            else if (pAtyp == 3) { val dlen = data[4].toInt() and 0xFF; responseBytes[off++] = dlen.toByte(); System.arraycopy(data, 5, responseBytes, off, dlen); off += dlen }
                                            else if (pAtyp == 4) { System.arraycopy(data, 4, responseBytes, off, 16); off += 16 }
                                            responseBytes[off++] = (targetPortNum shr 8).toByte(); responseBytes[off++] = (targetPortNum and 0xFF).toByte()
                                            System.arraycopy(dnsReply, 0, responseBytes, off, dnsReply.size)
                                            udpSocket.send(DatagramPacket(responseBytes, off + dnsReply.size, clientAddr, clientPort))
                                        } finally {
                                            ProxyStats.release8k(responseBytes)
                                        }
                                    }
                                } else {
                                    launch(Dispatchers.IO) {
                                        try {
                                            val res = RobustResolver.resolve(host, vpnService)
                                            if (res.isNotEmpty()) {
                                                val ipStrs = res.map { it.hostAddress ?: "" }.filter { it.isNotEmpty() }
                                                val dnsReply = DnsUtils.buildDnsReply(data, headerLen, payloadLen, ipStrs, query.qtype == 28)
                                                val headerSize = if (pAtyp == 1) 10 else if (pAtyp == 4) 22 else 7 + (data[4].toInt() and 0xFF)
                                                val responseBytes = ProxyStats.obtain8k()
                                                try {
                                                    var off = 0
                                                    responseBytes[off++] = 0; responseBytes[off++] = 0; responseBytes[off++] = 0; responseBytes[off++] = pAtyp.toByte()
                                                    if (pAtyp == 1) { System.arraycopy(data, 4, responseBytes, off, 4); off += 4 }
                                                    else if (pAtyp == 3) { val dlen = data[4].toInt() and 0xFF; responseBytes[off++] = dlen.toByte(); System.arraycopy(data, 5, responseBytes, off, dlen); off += dlen }
                                                    else if (pAtyp == 4) { System.arraycopy(data, 4, responseBytes, off, 16); off += 16 }
                                                    responseBytes[off++] = (targetPortNum shr 8).toByte(); responseBytes[off++] = (targetPortNum and 0xFF).toByte()
                                                    System.arraycopy(dnsReply, 0, responseBytes, off, dnsReply.size)
                                                    udpSocket.send(DatagramPacket(responseBytes, off + dnsReply.size, clientAddr, clientPort))
                                                } finally {
                                                    ProxyStats.release8k(responseBytes)
                                                }
                                            }
                                        } catch (e: Exception) {}
                                    }
                                }
                            }
                        } else {
                            val payload = data.copyOfRange(headerLen, len)
                            val cached = RobustResolver.getCached(targetHost)
                            if (cached != null && cached.isNotEmpty()) {
                                udpOutChannel.trySend(DatagramPacket(payload, payload.size, cached.first(), targetPortNum) to targetHost)
                            } else {
                                launch(Dispatchers.IO) {
                                    try {
                                        val res = RobustResolver.resolve(targetHost, vpnService)
                                        if (res.isNotEmpty()) {
                                            udpOutChannel.trySend(DatagramPacket(payload, payload.size, res.first(), targetPortNum) to targetHost)
                                        }
                                    } catch (e: Exception) {}
                                }
                            }
                        }
                    }
                } catch (e: Exception) {
                    if (e !is CancellationException) Log.v("UdpTransport", "Client->Target error: ${e.message}")
                } finally {
                    ProxyStats.release64k(buffer)
                    udpOutChannel.close()
                }
            }
            
            // Keep TCP connection alive, monitor for closure
            launch(Dispatchers.IO) {
                try {
                    outSocket.soTimeout = 5000
                    udpSocket.soTimeout = 5000
                    val inputStream = clientSocket.getInputStream()
                    while (isActive) {
                        if (inputStream.read() == -1) break
                    }
                } catch (e: Exception) {
                } finally {
                    jobs.forEach { it.cancel() }
                }
            }
        }
        try { outSocket.close() } catch (e: Exception) {}
        try { udpSocket.close() } catch (e: Exception) {}
    }

    private suspend fun sendUdpPacket(socket: DatagramSocket, packet: DatagramPacket, targetHost: String = "") {
        val payload = packet.data
        val offset = packet.offset
        val length = packet.length
        val targetInet = packet.address
        val targetPort = packet.port
        
        val isQuic = targetPort == 443 && length > 0 && (payload[offset].toInt() and 0xC0) == 0xC0
        
        // Basic filtering
        if (BypassConfig.blockQuic && isQuic) return

        val host = if (targetHost.isNotEmpty()) targetHost else targetInet.hostAddress
        val strategy = BypassConfig.getBestStrategyForHost(host)
        val config = BypassConfig.getSessionConfig(host, strategy, BypassConfig.currentRttMs.value)
        
        // Adaptive Jitter
        val intensity = ProxyStats.censorshipIntensity.value
        val rnd = ThreadLocalRandom.current()
        if (intensity > 40) {
            val jitter = rnd.nextLong(0, (intensity / 5).toLong() + 5)
            if (jitter > 0) delay(jitter)
        }

        // Apply centralized UDP bypass
        BypassConfig.applyUdpBypass(socket, packet, config, host)
    }
}
