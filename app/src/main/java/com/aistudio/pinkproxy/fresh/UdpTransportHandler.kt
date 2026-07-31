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

    private val hostStrategyCache = ConcurrentHashMap<String, Pair<SessionConfig, Long>>(100)

    suspend fun handleUdpAssociate(
        clientSocket: Socket,
        output: java.io.OutputStream,
        vpnService: VpnService,
        scope: CoroutineScope
    ) {
        // Open DatagramSocket to receive SOCKS5 UDP packets
        val udpSocket = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val localPort = udpSocket.localPort
        
        // Multiple outgoing sockets, one per worker, to avoid race conditions on socket options (like TTL)
        val outSockets = Array(8) { 
            DatagramSocket().apply { try { vpnService.protect(this) } catch (e: Throwable) {} }
        }
        
        try {
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
            
            val udpOutChannels = Array(8) { kotlinx.coroutines.channels.Channel<Pair<DatagramPacket, String>>(500) }
            
            coroutineScope {
                val jobs = mutableListOf<Job>()
                
                // Outgoing UDP Workers (each with its own socket)
                repeat(8) { i ->
                    val outSocket = outSockets[i]
                    jobs += launch(ProxyDispatcher.io) {
                        val activeSessions = ConcurrentHashMap<String, Long>()
                        
                        // Heartbeat job for this worker's sessions
                        val hbJob = launch {
                            val rnd = ThreadLocalRandom.current()
                            while (isActive) {
                                delay(rnd.nextLong(20000, 45000))
                                val now = System.currentTimeMillis()
                                activeSessions.entries.removeIf { now - it.value > 60000 }
                                
                                for (session in activeSessions.keys) {
                                    val parts = session.split(":")
                                    if (parts.size == 2) {
                                        try {
                                            val addr = InetAddress.getByName(parts[0])
                                            val port = parts[1].toInt()
                                            // Send realistic noise instead of 0x00
                                            val noise = if (port == 443) FakePacketHelper.buildUdpNoise(rnd.nextInt(1, 10)) else byteArrayOf(0x00)
                                            outSocket.send(DatagramPacket(noise, noise.size, addr, port))
                                        } catch (e: Throwable) {}
                                    }
                                }
                            }
                        }
                        
                        try {
                            for (work in udpOutChannels[i]) {
                                val (packet, targetHost) = work
                                activeSessions["${packet.address.hostAddress}:${packet.port}"] = System.currentTimeMillis()
                                try {
                                    sendUdpPacket(outSocket, packet, targetHost)
                                } catch (e: Throwable) {
                                    if (e is CancellationException) throw e
                                    Log.v("UdpTransport", "Send error: ${e.message}")
                                }
                            }
                        } catch (e: Throwable) {
                            if (e is CancellationException) throw e
                            Log.v("UdpTransport", "UDP Outbound worker error: ${e.message}")
                        } finally {
                            hbJob.cancel()
                        }
                    }
                }

                // Receive from Target workers (one per outbound socket)
                repeat(8) { i ->
                    val outSocket = outSockets[i]
                    jobs += launch(ProxyDispatcher.io) {
                        val buffer = ProxyStats.obtain64k()
                        val respBuffer = ProxyStats.obtain64k()
                        val packet = DatagramPacket(buffer, buffer.size)
                        val outPacket = DatagramPacket(respBuffer, respBuffer.size)
                        try {
                            outSocket.soTimeout = 2000
                            while (isActive) {
                                packet.setData(buffer)
                                try {
                                    outSocket.receive(packet)
                                } catch (e: java.net.SocketTimeoutException) {
                                    continue
                                } catch (e: Throwable) {
                                    if (e is CancellationException) throw e
                                    break
                                }

                                if (clientUdpAddress != null) {
                                    val addrBytes = packet.address.address
                                    var offset = 0
                                    respBuffer[offset++] = 0; respBuffer[offset++] = 0; respBuffer[offset++] = 0
                                    if (addrBytes.size == 4) { respBuffer[offset++] = 1 } else { respBuffer[offset++] = 4 }
                                    System.arraycopy(addrBytes, 0, respBuffer, offset, addrBytes.size); offset += addrBytes.size
                                    respBuffer[offset++] = (packet.port shr 8).toByte(); respBuffer[offset++] = (packet.port and 0xFF).toByte()
                                    System.arraycopy(packet.data, packet.offset, respBuffer, offset, packet.length); offset += packet.length
                                    
                                    outPacket.address = clientUdpAddress
                                    outPacket.port = clientUdpPort
                                    outPacket.setData(respBuffer, 0, offset)
                                    udpSocket.send(outPacket)
                                    ProxyStats.updateBytes(packet.length.toLong())
                                }
                            }
                        } catch (e: Throwable) {
                            if (e !is CancellationException) Log.v("UdpTransport", "Target->Client error: ${e.message}")
                        } finally {
                            when (buffer.size) { 8192 -> ProxyStats.release8k(buffer); 16384 -> ProxyStats.release16k(buffer); 65536 -> ProxyStats.release64k(buffer); else -> {} }
                            when (respBuffer.size) { 8192 -> ProxyStats.release8k(respBuffer); 16384 -> ProxyStats.release16k(respBuffer); 65536 -> ProxyStats.release64k(respBuffer); else -> {} }
                        }
                    }
                }

                // Receive from SOCKS5 Client, forward to Target
                jobs += launch(ProxyDispatcher.io) {
                    val buffer = ProxyStats.obtain64k()
                    val packet = DatagramPacket(buffer, buffer.size)
                    try {
                        udpSocket.soTimeout = 2000
                        while (isActive) {
                            packet.setData(buffer)
                            try {
                                udpSocket.receive(packet)
                            } catch (e: java.net.SocketTimeoutException) {
                                continue
                            } catch (e: Throwable) {
                                if (e is CancellationException) throw e
                                break
                            }
                            val pktAddr = packet.address ?: continue
                            val pktPort = packet.port
                            if (clientUdpAddress == null) {
                                if (pktAddr.isLoopbackAddress || pktAddr.hostAddress == "127.0.0.1") {
                                    clientUdpAddress = pktAddr
                                    clientUdpPort = pktPort
                                } else {
                                    continue
                                }
                            } else {
                                if (pktAddr != clientUdpAddress || pktPort != clientUdpPort) {
                                    continue
                                }
                            }
                            
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
                            
                            ProxyStats.addTraffic(targetHost)
                            val payloadLen = len - headerLen
                            ProxyStats.updateBytes(payloadLen.toLong())
                            
                            // Schedule TTL probe for new UDP targets
                            AutoTtlProber.scheduleProbe(targetHost, targetPortNum, vpnService, scope)

                            val strategy = BypassConfig.getBestStrategyForHost(targetHost)
                            if (targetPortNum == 53 || strategy == BypassStrategy.DNS_OVER_TCP_FORCE) {
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
                                        launch(ProxyDispatcher.io) {
                                            try {
                                                val res = if (strategy == BypassStrategy.DNS_OVER_TCP_FORCE) {
                                                    RobustResolver.resolveDnsOverTcpOnly(host, vpnService)
                                                } else {
                                                    RobustResolver.resolve(host, vpnService)
                                                }
                                                if (res.isNotEmpty()) {
                                                    val ipStrs = res.map { it.hostAddress ?: "" }.filter { it.isNotEmpty() }
                                                    val dnsReply = DnsUtils.buildDnsReply(data, headerLen, payloadLen, ipStrs, query.qtype == 28)
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
                                            } catch (e: Throwable) {}
                                        }
                                    }
                                }
                            } else {
                                val payload = data.copyOfRange(headerLen, len)
                                val cached = RobustResolver.getCached(targetHost)
                                if (cached != null && cached.isNotEmpty()) {
                                    val hash = (targetHost.hashCode() xor targetPortNum)
                                    val workerIdx = Math.abs(hash) % 8
                                    udpOutChannels[workerIdx].trySend(DatagramPacket(payload, payload.size, cached.first(), targetPortNum) to targetHost)
                                } else {
                                    launch(ProxyDispatcher.io) {
                                        try {
                                            val res = RobustResolver.resolve(targetHost, vpnService)
                                            if (res.isNotEmpty()) {
                                                val hash2 = (targetHost.hashCode() xor targetPortNum)
                                                val workerIdx2 = Math.abs(hash2) % 8
                                                udpOutChannels[workerIdx2].trySend(DatagramPacket(payload, payload.size, res.first(), targetPortNum) to targetHost)
                                            }
                                        } catch (e: Throwable) {}
                                    }
                                }
                            }
                        }
                    } catch (e: Throwable) {
                        if (e !is CancellationException) Log.v("UdpTransport", "Client->Target error: ${e.message}")
                    } finally {
                        when (buffer.size) { 8192 -> ProxyStats.release8k(buffer); 16384 -> ProxyStats.release16k(buffer); 65536 -> ProxyStats.release64k(buffer); else -> {} }
                        udpOutChannels.forEach { it.close() }
                    }
                }
                
                // Keep TCP connection alive, monitor for closure
                launch(ProxyDispatcher.io) {
                    try {
                        clientSocket.soTimeout = 0
                        val inputStream = clientSocket.getInputStream()
                        while (isActive) {
                            if (inputStream.read() == -1) break
                        }
                    } catch (e: Throwable) {
                    } finally {
                        jobs.forEach { it.cancel() }
                    }
                }
            }
        } catch (e: Throwable) {
            if (e !is CancellationException) Log.e("UdpTransport", "handleUdpAssociate error", e)
        } finally {
            outSockets.forEach { try { it.close() } catch (e: Throwable) {} }
            try { udpSocket.close() } catch (e: Throwable) {}
        }
    }

    private val reorderBuffers = ConcurrentHashMap<String, MutableList<DatagramPacket>>()
    private val reorderMutex = Any()
    private var lastReorderBufferCleanup = System.currentTimeMillis()

    private val flowPacketCounter = ConcurrentHashMap<String, java.util.concurrent.atomic.AtomicInteger>()

    private fun isQuicInitial(data: ByteArray, offset: Int, length: Int): Boolean {
        if (length < 200) return false
        val firstByte = data[offset].toInt() and 0xFF
        // Long header (0x80), bit 6 fixed to 1 (0x40), Type Initial (0x00)
        return (firstByte and 0x80) != 0 && (firstByte and 0x40) != 0 && (firstByte and 0x30) == 0x00
    }

    private suspend fun sendUdpPacket(socket: DatagramSocket, packet: DatagramPacket, targetHost: String = "") {
        if (System.currentTimeMillis() - lastReorderBufferCleanup > 60000) {
            synchronized(reorderMutex) {
                lastReorderBufferCleanup = System.currentTimeMillis()
                if (reorderBuffers.size > 200) {
                    reorderBuffers.clear()
                }
            }
            if (flowPacketCounter.size > 500) flowPacketCounter.clear()
        }
        
        val payload = packet.data
        val offset = packet.offset
        val length = packet.length
        val targetInet = packet.address ?: return
        val targetPort = packet.port
        
        val isQuic = targetPort == 443 && length > 0 && ((payload[offset].toInt() and 0xC0) == 0xC0 || (payload[offset].toInt() and 0x80) != 0)
        val isDns = targetPort == 53 || targetPort == 853 || targetPort == 784
        
        // Basic filtering
        if (BypassConfig.blockQuic && isQuic) {
            // Force immediate fallback by sending Version Negotiation back to client
            if (isQuicInitial(payload, offset, length)) {
                try {
                    val dcidLen = payload[offset + 5].toInt() and 0xFF
                    if (length > 6 + dcidLen) {
                        val dcid = payload.copyOfRange(offset + 6, offset + 6 + dcidLen)
                        val scidOffset = offset + 6 + dcidLen
                        val scidLen = payload[scidOffset].toInt() and 0xFF
                        if (length > scidOffset + 1 + scidLen) {
                             val scid = payload.copyOfRange(scidOffset + 1, scidOffset + 1 + scidLen)
                             val vn = FakePacketHelper.buildQuicVersionNegotiation(dcid, scid)
                             socket.send(DatagramPacket(vn, vn.size, packet.address, packet.port))
                        }
                    }
                } catch (e: Throwable) {}
            }
            return
        }

        val host = if (targetHost.isNotEmpty()) targetHost else targetInet.hostAddress ?: ""
        val flowKey = "${targetInet.hostAddress}:$targetPort"
        
        // 0. Periodic Flow Noise Injection
        val counter = flowPacketCounter.getOrPut(flowKey) { java.util.concurrent.atomic.AtomicInteger(0) }
        val count = counter.incrementAndGet()
        
        // Optimization: For high-volume flows (count > 50), bypass some heavy obfuscation to save CPU
        val isHighVolume = count > 50
        
        if (!isDns) {
            // Random Jitter/Delay - skip for high volume to maintain performance
            val intensity = ProxyStats.censorshipIntensity.value
            if (!isHighVolume && intensity > 60 && ThreadLocalRandom.current().nextInt(100) < 5) {
                delay(ThreadLocalRandom.current().nextLong(1, 5))
            }

            if (!isHighVolume && count % 20 == 0) { // Every 20 packets, but only for initial burst
                val rnd = ThreadLocalRandom.current()
                if (rnd.nextInt(100) < (intensity / 2).coerceIn(10, 50)) {
                    val noiseSize = if (isQuic) rnd.nextInt(256, 1024) else rnd.nextInt(16, 64)
                    val noise = FakePacketHelper.buildUdpNoise(noiseSize)
                    try { socket.send(DatagramPacket(noise, noise.size, targetInet, targetPort)) } catch(e: Throwable) {}
                }
            }
            
            // UDP Reorder Simulation for certain flows (QUIC)
            if (!isHighVolume && isQuic && intensity > 70 && count < 10) {
                 if (ThreadLocalRandom.current().nextInt(100) < 15) {
                     // Save this packet for a very short time and let next one pass first
                     val buffer = reorderBuffers.getOrPut(flowKey) { mutableListOf() }
                     if (buffer.size < 2) {
                         buffer.add(DatagramPacket(payload.copyOfRange(offset, offset + length), length, targetInet, targetPort))
                         return
                     }
                 }
            }
        }
        
        val now = System.currentTimeMillis()
        val cached = hostStrategyCache[host]
        
        val config = if (cached == null || now - cached.second > 15000L) {
            val strat = BypassConfig.getBestStrategyForHost(host)
            val cfg = BypassConfig.getSessionConfig(host, strat, BypassConfig.currentRttMs.value)
            if (hostStrategyCache.size > 500) hostStrategyCache.clear() 
            hostStrategyCache[host] = cfg to now
            cfg
        } else {
            cached.first
        }

        // Adaptive Jitter and TTL randomization
        val intensity = ProxyStats.censorshipIntensity.value
        val rnd = ThreadLocalRandom.current()
        
        // 1. Shadowing: occasionally send a fake UDP handshake before real data (Only for session start)
        if (!isHighVolume && intensity > 55 && count < 5 && rnd.nextInt(100) < 15) {
            val shadow = when(rnd.nextInt(4)) {
                0 -> FakePacketHelper.buildWireguardFake()
                1 -> FakePacketHelper.buildOpenVpnFake()
                2 -> FakePacketHelper.buildQuicInitialFake()
                else -> FakePacketHelper.buildProtocolConfusion("DTLS")
            }
            socket.send(DatagramPacket(shadow, shadow.size, targetInet, targetPort))
            if (intensity > 80) delay(rnd.nextLong(1, 5))
        }

        // 2. QUIC-Specific Obfuscation
        if (!isHighVolume && isQuic && intensity > 70 && count < 3 && rnd.nextInt(100) < 30) {
            if (isQuicInitial(payload, offset, length)) {
                 // Extreme Obfuscation: send a Quic Retry first to "reset" DPI state
                 if (intensity > 85 && rnd.nextInt(100) < 25) {
                     val dcidLen = payload[offset + 5].toInt() and 0xFF
                     if (length > 6 + dcidLen + 20) {
                         val dcid = payload.copyOfRange(offset + 6, offset + 6 + dcidLen)
                         val scidOffset = offset + 6 + dcidLen
                         val scidLen = payload[scidOffset].toInt() and 0xFF
                         if (length > scidOffset + 1 + scidLen) {
                             val scid = payload.copyOfRange(scidOffset + 1, scidOffset + 1 + scidLen)
                             val retry = FakePacketHelper.buildQuicRetry(dcid, scid, FakePacketHelper.buildUdpNoise(16))
                             socket.send(DatagramPacket(retry, retry.size, targetInet, targetPort))
                             delay(rnd.nextLong(1, 4))
                         }
                     }
                 }
                 
                  if (config.strategy == BypassStrategy.UDP_OVERLAP_SKEW) {
                      val split = rnd.nextInt(50, 150)
                      val fake = FakePacketHelper.buildUdpNoise(split)
                      TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5), targetInet is java.net.Inet6Address)
                      socket.send(DatagramPacket(fake, fake.size, targetInet, targetPort))
                      delay(rnd.nextLong(1, 3))
                      TtlHelper.setUdpTtl(socket, 64, targetInet is java.net.Inet6Address)
                      socket.send(DatagramPacket(payload, offset, length, targetInet, targetPort))
                      return
                  }

                 // Fragmented Initial strategy
                 if (BypassConfig.strategy.value == BypassStrategy.UDP_FRAGMENT_SKEW || intensity > 90) {
                     val split = rnd.nextInt(100, 300)
                     socket.send(DatagramPacket(payload, offset, split, targetInet, targetPort))
                     delay(rnd.nextLong(1, 5))
                     socket.send(DatagramPacket(payload, offset + split, length - split, targetInet, targetPort))
                     return
                 }
            }
            
            val fakeInitial = FakePacketHelper.buildQuicInitialExtremePadding()
            TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5), targetInet is java.net.Inet6Address)
            socket.send(DatagramPacket(fakeInitial, fakeInitial.size, targetInet, targetPort))
            
            // Added: Version Negotiation chaos
            if (intensity > 85) {
                val chaos = FakePacketHelper.buildQuicVersionChaos()
                socket.send(DatagramPacket(chaos, chaos.size, targetInet, targetPort))
            }

            delay(1)
            TtlHelper.setUdpTtl(socket, 64, targetInet is java.net.Inet6Address)
        }

        // 3. Reordering Logic for QUIC or explicit UDP_REORDER
        if (!isHighVolume && (config.strategy == BypassStrategy.UDP_REORDER || (isQuic && intensity > 80 && rnd.nextInt(100) < 20))) {
            val key = "${targetInet.hostAddress}:$targetPort"
            val buffer = reorderBuffers.getOrPut(key) { Collections.synchronizedList(mutableListOf<DatagramPacket>()) }
            
            val pCopy = DatagramPacket(payload.copyOfRange(offset, offset + length), length, targetInet, targetPort)
            buffer.add(pCopy)
            
            if (buffer.size >= 2 + rnd.nextInt(2)) {
                val toSend = buffer.toMutableList().apply { shuffle() }
                buffer.clear()
                for (p in toSend) {
                    BypassConfig.applyUdpBypass(socket, p, config, host)
                    if (rnd.nextInt(100) < 30) delay(rnd.nextLong(1, 3))
                }
            }
            return
        }

        if (intensity > 35) {
            val jitter = rnd.nextLong(0, (intensity / 6).toLong() + 3)
            if (jitter > 0) delay(jitter)
            
            // Pad UDP packets to prevent size fingerprinting
            if (intensity > 65 && length < 1200 && !isDns) {
                val targetSize = if (length < 512) 512 else if (length < 1024) 1024 else 1280
                val paddedData = ByteArray(targetSize)
                System.arraycopy(payload, offset, paddedData, 0, length)
                // We don't really need to fill with noise if it's just for size, but some DPIs check entropy
                if (intensity > 85) {
                    val noise = ByteArray(targetSize - length)
                    rnd.nextBytes(noise)
                    System.arraycopy(noise, 0, paddedData, length, noise.size)
                }
                socket.send(DatagramPacket(paddedData, targetSize, targetInet, targetPort))
                return
            }
        }
        
        if (config.strategy == BypassStrategy.UDP_STUTTER) {
            val chunks = rnd.nextInt(2, 5)
            var pos = 0
            for (i in 0 until chunks) {
                val sz = if (i == chunks - 1) length - pos else (length / chunks)
                if (sz > 0) {
                    socket.send(DatagramPacket(payload, offset + pos, sz, targetInet, targetPort))
                    pos += sz
                    delay(rnd.nextLong(2, 12))
                }
            }
            return
        }

        if (config.strategy == BypassStrategy.UDP_PADDING_CHAOS) {
            val targetSize = rnd.nextInt(1200, 1400)
            if (length < targetSize) {
                val padded = ByteArray(targetSize)
                System.arraycopy(payload, offset, padded, 0, length)
                val noise = ByteArray(targetSize - length)
                rnd.nextBytes(noise)
                System.arraycopy(noise, 0, padded, length, noise.size)
                socket.send(DatagramPacket(padded, targetSize, targetInet, targetPort))
                return
            }
        }

        // 4. Packet Stuttering: for new sessions, delay initial packets slightly more
        if (intensity > 65 && !hostStrategyCache.containsKey(host)) {
             delay(rnd.nextLong(10, 40))
        }
        
        // Randomize TTL slightly to avoid fingerprinting fixed TTL values
        if (rnd.nextInt(100) < 20) {
            val isIpv6 = targetInet is java.net.Inet6Address
            val randomTtl = rnd.nextInt(58, 68)
            TtlHelper.setUdpTtl(socket, randomTtl, isIpv6)
        }

        // 5. Packet-Level Mangle: Fragmentation, Padding and Reordering
        if (length > 200 && !isDns && intensity > 40) {
            val shouldFrag = config.strategy == BypassStrategy.UDP_DATA_FRAG || (intensity > 60 && rnd.nextInt(100) < 25)
            if (shouldFrag) {
                val split = rnd.nextInt(64, length - 64)
                val shouldReorder = intensity > 80 && rnd.nextInt(100) < 30
                
                if (shouldReorder) {
                    // Send second part first
                    socket.send(DatagramPacket(payload, offset + split, length - split, targetInet, targetPort))
                    delay(rnd.nextLong(1, 5))
                    socket.send(DatagramPacket(payload, offset, split, targetInet, targetPort))
                } else {
                    // First part
                    socket.send(DatagramPacket(payload, offset, split, targetInet, targetPort))
                    if (intensity > 60) delay(rnd.nextLong(1, 4))
                    // Second part
                    socket.send(DatagramPacket(payload, offset + split, length - split, targetInet, targetPort))
                }
                
                // Optional shadow packet to confuse DPI
                if (intensity > 85 && rnd.nextInt(100) < 15) {
                    val shadow = FakePacketHelper.buildUdpNoise(rnd.nextInt(10, 40))
                    val isIpv6 = targetInet is java.net.Inet6Address
                    try {
                        TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5), isIpv6)
                        socket.send(DatagramPacket(shadow, shadow.size, targetInet, targetPort))
                    } catch (e: Throwable) {}
                }
                return
            }
        }

        // Apply centralized UDP bypass
        BypassConfig.applyUdpBypass(socket, packet, config, host)
    }
}
