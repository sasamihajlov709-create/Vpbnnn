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
            repeat(4) {
                jobs += launch(Dispatchers.IO) {
                    try {
                        for (work in udpOutChannel) {
                            val (packet, targetHost) = work
                            sendUdpPacket(outSocket, packet.data.copyOfRange(packet.offset, packet.offset + packet.length), packet.address, packet.port, targetHost)
                        }
                    } catch (e: Exception) {
                        if (e !is CancellationException) Log.v("UdpTransport", "UDP Outbound worker error: ${e.message}")
                    }
                }
            }

            // Receive from Target, forward to SOCKS5 Client
            jobs += launch(Dispatchers.IO) {
                val buffer = ProxyStats.obtain64k()
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
                            val respBytes = ByteArray(packet.length + 22)
                            var offset = 0
                            respBytes[offset++] = 0; respBytes[offset++] = 0; respBytes[offset++] = 0
                            if (addrBytes.size == 4) { respBytes[offset++] = 1 } else { respBytes[offset++] = 4 }
                            System.arraycopy(addrBytes, 0, respBytes, offset, addrBytes.size); offset += addrBytes.size
                            respBytes[offset++] = (packet.port shr 8).toByte(); respBytes[offset++] = (packet.port and 0xFF).toByte()
                            System.arraycopy(packet.data, packet.offset, respBytes, offset, packet.length); offset += packet.length
                            udpSocket.send(DatagramPacket(respBytes, offset, clientUdpAddress, clientUdpPort))
                            ProxyStats.updateBytes(packet.length.toLong())
                        }
                    }
                } catch (e: Exception) {
                    if (e !is CancellationException) Log.v("UdpTransport", "Target->Client error: ${e.message}")
                } finally {
                    ProxyStats.release64k(buffer)
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
                                val ipBytes = data.copyOfRange(4, 8)
                                targetHost = InetAddress.getByAddress(ipBytes).hostAddress ?: ""
                            }
                            3 -> {
                                val dlen = data[4].toInt() and 0xFF
                                headerLen += 1 + dlen
                                if (len < headerLen + 2) continue
                                targetHost = String(data, 5, dlen)
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
                        
                        val payload = data.copyOfRange(headerLen, len)
                        ProxyStats.updateBytes(payload.size.toLong())
                        
                        if (targetPortNum == 53) {
                            val query = DnsUtils.parseDnsQName(payload)
                            if (query != null) {
                                val resolvedIps = RobustResolver.resolve(query.qname, vpnService)
                                if (resolvedIps.isNotEmpty()) {
                                    val ipStrs = resolvedIps.map { it.hostAddress ?: "" }.filter { it.isNotEmpty() }
                                    if (ipStrs.isNotEmpty()) {
                                        val dnsReply = DnsUtils.buildDnsReply(payload, ipStrs, query.qtype == 28)
                                        val headerSize = if (pAtyp == 1) 10 else if (pAtyp == 4) 22 else 7 + (data[4].toInt() and 0xFF)
                                        val responseBytes = ByteArray(headerSize + dnsReply.size)
                                        var offset = 0
                                        responseBytes[offset++] = 0; responseBytes[offset++] = 0; responseBytes[offset++] = 0; responseBytes[offset++] = pAtyp.toByte()
                                        if (pAtyp == 1) { System.arraycopy(data, 4, responseBytes, offset, 4); offset += 4 }
                                        else if (pAtyp == 3) { val dlen = data[4].toInt() and 0xFF; responseBytes[offset++] = dlen.toByte(); System.arraycopy(data, 5, responseBytes, offset, dlen); offset += dlen }
                                        else if (pAtyp == 4) { System.arraycopy(data, 4, responseBytes, offset, 16); offset += 16 }
                                        responseBytes[offset++] = (targetPortNum shr 8).toByte(); responseBytes[offset++] = (targetPortNum and 0xFF).toByte()
                                        System.arraycopy(dnsReply, 0, responseBytes, offset, dnsReply.size)
                                        offset += dnsReply.size
                                        udpSocket.send(DatagramPacket(responseBytes, offset, packet.address, packet.port))
                                    }
                                }
                            }
                        } else {
                            val resolved = RobustResolver.getCached(targetHost)
                            if (resolved != null && resolved.isNotEmpty()) {
                                udpOutChannel.trySend(DatagramPacket(payload, payload.size, resolved.first(), targetPortNum) to targetHost)
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
    }

    private suspend fun sendUdpPacket(socket: DatagramSocket, payload: ByteArray, targetInet: InetAddress, targetPort: Int, targetHost: String = "") {
        val isQuic = targetPort == 443 && payload.isNotEmpty() && (payload[0].toInt() and 0xC0) == 0xC0
        val outPacket = DatagramPacket(payload, payload.size, targetInet, targetPort)
        
        // Adaptive Jitter & Fragmentation
        val intensity = ProxyStats.censorshipIntensity.value
        val rnd = ThreadLocalRandom.current()
        if (intensity > 40) {
            val jitter = rnd.nextLong(0, (intensity / 5).toLong())
            if (jitter > 0) delay(jitter)
        }

        // UDP Fragmentation for large non-QUIC packets
        if (!isQuic && payload.size > 1200 && intensity > 70) {
            val mid = payload.size / 2
            val p1 = payload.copyOfRange(0, mid)
            val p2 = payload.copyOfRange(mid, payload.size)
            socket.send(DatagramPacket(p1, p1.size, targetInet, targetPort))
            delay(rnd.nextLong(2, 10))
            socket.send(DatagramPacket(p2, p2.size, targetInet, targetPort))
            return
        }

        val strategy = BypassConfig.getBestStrategyForHost(if (targetHost.isNotEmpty()) targetHost else targetInet.hostAddress)
        
        if (BypassConfig.blockQuic && isQuic) return

        if (strategy == BypassStrategy.UDP_STUN_FAKE) {
            val stun = FakePacketHelper.buildStunBindingRequest()
            socket.send(DatagramPacket(stun, stun.size, targetInet, targetPort))
            delay(rnd.nextLong(10, 50))
            socket.send(outPacket)
            return
        }

        if (strategy == BypassStrategy.UDP_FAKE_DTLS) {
            val dtls = FakePacketHelper.buildFakeDtlsClientHello()
            socket.send(DatagramPacket(dtls, dtls.size, targetInet, targetPort))
            delay(rnd.nextLong(15, 60))
            socket.send(outPacket)
            return
        }

        if (strategy == BypassStrategy.UDP_NOISE_PAD) {
            val noiseSize = if (isQuic) rnd.nextInt(1200, 1400) else rnd.nextInt(10, 100)
            val noise = FakePacketHelper.buildUdpNoise(noiseSize)
            socket.send(DatagramPacket(noise, noise.size, targetInet, targetPort))
            delay(rnd.nextLong(5, 25))
            socket.send(outPacket)
            return
        }

        if (strategy == BypassStrategy.DIRECT) {
            socket.send(outPacket)
            return
        }

        if (isQuic) {
            when (strategy) {
                BypassStrategy.QUIC_INITIAL_FAKE -> {
                    val fakeQuic = FakePacketHelper.buildQuicInitial()
                    val fakeQuicPacket = DatagramPacket(fakeQuic, fakeQuic.size, targetInet, targetPort)
                    TtlHelper.setUdpTtl(socket, 5, targetInet is java.net.Inet6Address)
                    socket.send(fakeQuicPacket)
                    delay(3)
                    TtlHelper.setUdpTtl(socket, 64, targetInet is java.net.Inet6Address)
                    socket.send(outPacket)
                }
                BypassStrategy.QUIC_RST_SKEW -> {
                    val rstPayload = FakePacketHelper.buildFakeUdpPacket(20)
                    val rstPacket = DatagramPacket(rstPayload, rstPayload.size, targetInet, targetPort)
                    TtlHelper.setUdpTtl(socket, 3, targetInet is java.net.Inet6Address)
                    socket.send(rstPacket)
                    delay(2)
                    TtlHelper.setUdpTtl(socket, 64, targetInet is java.net.Inet6Address)
                    socket.send(outPacket)
                }
                BypassStrategy.QUIC_VERSION_NEGOTIATION_SKEW -> {
                    val verPayload = ByteArray(100) { (it % 255).toByte() }
                    verPayload[0] = 0x80.toByte() 
                    verPayload[1] = 0; verPayload[2] = 0; verPayload[3] = 0; verPayload[4] = 0 
                    val verPacket = DatagramPacket(verPayload, verPayload.size, targetInet, targetPort)
                    TtlHelper.setUdpTtl(socket, 3, targetInet is java.net.Inet6Address)
                    socket.send(verPacket)
                    delay(5)
                    TtlHelper.setUdpTtl(socket, 64, targetInet is java.net.Inet6Address)
                    socket.send(outPacket)
                }
                BypassStrategy.UDP_DTLS_FAKE -> {
                    val dtls = byteArrayOf(0x16, 0xfe.toByte(), 0xff.toByte()) + ByteArray(20) { ThreadLocalRandom.current().nextInt(256).toByte() }
                    val dtlsPacket = DatagramPacket(dtls, dtls.size, targetInet, targetPort)
                    TtlHelper.setUdpTtl(socket, 5, targetInet is java.net.Inet6Address)
                    socket.send(dtlsPacket)
                    delay(3)
                    TtlHelper.setUdpTtl(socket, 64, targetInet is java.net.Inet6Address)
                    socket.send(outPacket)
                }
                BypassStrategy.UDP_GHOST_SKEW -> {
                    repeat(ThreadLocalRandom.current().nextInt(1, 3)) {
                        val ghost = FakePacketHelper.buildFakeUdpPacket(ThreadLocalRandom.current().nextInt(10, 40))
                        val ghostPacket = DatagramPacket(ghost, ghost.size, targetInet, targetPort)
                        TtlHelper.setUdpTtl(socket, 2, targetInet is java.net.Inet6Address)
                        socket.send(ghostPacket)
                        delay(2)
                    }
                    TtlHelper.setUdpTtl(socket, 64, targetInet is java.net.Inet6Address)
                    socket.send(outPacket)
                }
                BypassStrategy.UDP_FRAGMENT_SKEW -> {
                    if (payload.size > 20) {
                        val p1 = payload.copyOfRange(0, 10)
                        val p2 = payload.copyOfRange(10, payload.size)
                        socket.send(DatagramPacket(p1, p1.size, targetInet, targetPort))
                        delay(1)
                        socket.send(DatagramPacket(p2, p2.size, targetInet, targetPort))
                    } else {
                        socket.send(outPacket)
                    }
                }
                BypassStrategy.UDP_STUTTER -> {
                    delay(ThreadLocalRandom.current().nextLong(1, 5))
                    socket.send(outPacket)
                }
                BypassStrategy.QUIC_MTU_PROBE -> {
                    socket.send(outPacket)
                    val probe = ProxyStats.obtain8k()
                    try {
                        java.util.Arrays.fill(probe, 0.toByte())
                        repeat(2) {
                            delay(5)
                            socket.send(DatagramPacket(probe, 1200, targetInet, targetPort))
                        }
                    } finally {
                        ProxyStats.release8k(probe)
                    }
                }
                else -> {
                    val fakeQuic = FakePacketHelper.buildQuicInitial()
                    val fakeQuicPacket = DatagramPacket(fakeQuic, fakeQuic.size, targetInet, targetPort)
                    TtlHelper.setUdpTtl(socket, 5, targetInet is java.net.Inet6Address)
                    socket.send(fakeQuicPacket)
                    delay(3)
                    TtlHelper.setUdpTtl(socket, 64, targetInet is java.net.Inet6Address)
                    socket.send(outPacket)
                }
            }
        } else if (targetPort == 53) {
            when (strategy) {
                BypassStrategy.DNS_NOISE -> {
                    val noise = FakePacketHelper.buildFakeUdpPacket(50)
                    val noisePacket = DatagramPacket(noise, noise.size, targetInet, targetPort)
                    TtlHelper.setUdpTtl(socket, 4, targetInet is java.net.Inet6Address)
                    socket.send(noisePacket)
                    delay(2)
                    TtlHelper.setUdpTtl(socket, 64, targetInet is java.net.Inet6Address)
                    socket.send(outPacket)
                }
                else -> {
                    val noise = FakePacketHelper.buildQuicInitial()
                    val noisePacket = DatagramPacket(noise, noise.size, targetInet, targetPort)
                    TtlHelper.setUdpTtl(socket, 5, targetInet is java.net.Inet6Address)
                    socket.send(noisePacket)
                    delay(3)
                    TtlHelper.setUdpTtl(socket, 64, targetInet is java.net.Inet6Address)
                    socket.send(outPacket)
                }
            }
        } else {
            val noise = FakePacketHelper.buildFakeUdpPacket(ThreadLocalRandom.current().nextInt(30, 150))
            val noisePacket = DatagramPacket(noise, noise.size, targetInet, targetPort)
            TtlHelper.setUdpTtl(socket, 5, targetInet is java.net.Inet6Address)
            socket.send(noisePacket)
            delay(3)
            TtlHelper.setUdpTtl(socket, 64, targetInet is java.net.Inet6Address)
            socket.send(outPacket)
        }
    }
}
