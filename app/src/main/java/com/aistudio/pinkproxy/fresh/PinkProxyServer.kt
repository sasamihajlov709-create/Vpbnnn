package com.aistudio.pinkproxy.fresh

import android.content.Context
import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.net.*
import java.nio.ByteBuffer
import java.util.*
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.io.*
class PinkProxyServer(private val vpnService: VpnService, private val port: Int) {
    private var proxyDispatcher: ExecutorCoroutineDispatcher? = null
    private var serverJob: Job? = null
    private var serverSocket: ServerSocket? = null
    
    fun start() {
        if (serverJob?.isActive == true) return
        
        val dispatcher = Executors.newCachedThreadPool().asCoroutineDispatcher()
        proxyDispatcher = dispatcher
        val parentJob = SupervisorJob()
        val scope = CoroutineScope(dispatcher + parentJob)
        serverJob = parentJob
        
        ProxyStats.startSpeedMonitor(scope)
        
        
        scope.launch {
            try {
                serverSocket = ServerSocket().apply {
                    reuseAddress = true
                    bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port))
                }
                ProxyStats.logRecovery("Proxy server started on port $port")
                while (isActive) {
                    val client = try {
                        serverSocket?.accept()
                    } catch (e: SocketException) {
                        null
                    } ?: break
                    
                    launch { handleClient(client) }
                }
            } catch (e: Exception) {
                if (isActive) Log.e("PinkProxy", "Server error", e)
            } finally {
                try { serverSocket?.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                serverSocket = null
            }
        }
    }

    fun stop() {
        serverJob?.cancel()
        try { serverSocket?.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        serverSocket = null
        proxyDispatcher?.close()
        proxyDispatcher = null
    }

    private suspend fun readExactly(input: InputStream, buffer: ByteArray, offset: Int, length: Int) {
        var read = 0
        while (read < length) {
            val r = input.read(buffer, offset + read, length - read)
            if (r == -1) throw IOException("EOF")
            read += r
        }
    }

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    private suspend fun handleClient(client: Socket) {
        ProxyStats.updateConnections(1)
        var targetSocket: Socket? = null
        try {
            client.soTimeout = 15000
            val input = client.getInputStream()
            val output = client.getOutputStream()

            // SOCKS5 Handshake
            val handshakeHeader = ByteArray(2)
            readExactly(input, handshakeHeader, 0, 2)
            if (handshakeHeader[0].toInt() != 5) {
                client.close()
                return
            }
            val numMethods = handshakeHeader[1].toInt() and 0xFF
            val methods = ByteArray(numMethods)
            readExactly(input, methods, 0, numMethods)
            output.write(byteArrayOf(5, 0)) // No authentication
            output.flush()

            // Command request
            val requestHeader = ByteArray(4)
            readExactly(input, requestHeader, 0, 4)
            val ver2 = requestHeader[0].toInt()
            val cmd = requestHeader[1].toInt()
            val atyp = requestHeader[3].toInt()

            if (ver2 != 5 || (cmd != 1 && cmd != 3)) { // Only CONNECT and UDP ASSOCIATE supported
                client.close()
                return
            }
            
            if (cmd == 3) { // UDP ASSOCIATE
                val atypUdp = atyp
                val addrBytesUdp = when (atypUdp) {
                    1 -> { val b = ByteArray(4); readExactly(input, b, 0, 4); b }
                    3 -> { val len = input.read(); val b = ByteArray(len); readExactly(input, b, 0, len); b }
                    4 -> { val b = ByteArray(16); readExactly(input, b, 0, 16); b }
                    else -> { client.close(); return }
                }
                val portUdpBytes = ByteArray(2)
                readExactly(input, portUdpBytes, 0, 2)
                
                // Open DatagramSocket to receive SOCKS5 UDP packets
                val udpSocket = java.net.DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
                val localPort = udpSocket.localPort
                
                // One outgoing socket for the entire UDP associate session
                val outSocket = java.net.DatagramSocket()
                try { vpnService.protect(outSocket) } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }

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
                
                // UDP Worker pool for outgoing packets
                val udpOutChannel = kotlinx.coroutines.channels.Channel<Pair<java.net.DatagramPacket, String>>(100)
                
                coroutineScope {
                    // Outgoing UDP Workers
                    repeat(4) {
                        launch(Dispatchers.IO) {
                            for (work in udpOutChannel) {
                                try {
                                    val (packet, targetHost) = work
                                    sendUdpPacket(outSocket, packet.data.copyOfRange(packet.offset, packet.offset + packet.length), packet.address, packet.port, targetHost)
                                } catch (e: Exception) {
                                    android.util.Log.v("PinkProxy", "UDP Outbound worker error: ${e.message}")
                                }
                            }
                        }
                    }

                    // Receive from Target, forward to SOCKS5 Client
                    launch(Dispatchers.IO) {
                        val buffer = ProxyStats.obtain64k()
                        val packet = java.net.DatagramPacket(buffer, buffer.size)
                        try {
                            while (isActive) {
                                packet.setData(buffer)
                                outSocket.receive(packet)
                                if (clientUdpAddress != null) {
                                    val addrBytes = packet.address.address
                                    val respBytes = ByteArray(packet.length + 22)
                                    var offset = 0
                                    respBytes[offset++] = 0; respBytes[offset++] = 0; respBytes[offset++] = 0
                                    if (addrBytes.size == 4) { respBytes[offset++] = 1 } else { respBytes[offset++] = 4 }
                                    System.arraycopy(addrBytes, 0, respBytes, offset, addrBytes.size); offset += addrBytes.size
                                    respBytes[offset++] = (packet.port shr 8).toByte(); respBytes[offset++] = (packet.port and 0xFF).toByte()
                                    System.arraycopy(packet.data, packet.offset, respBytes, offset, packet.length); offset += packet.length
                                    udpSocket.send(java.net.DatagramPacket(respBytes, offset, clientUdpAddress, clientUdpPort))
                                }
                            }
                        } catch (e: Exception) {
                        } finally {
                            ProxyStats.release64k(buffer)
                        }
                    }

                    // Receive from SOCKS5 Client, forward to Target
                    launch(Dispatchers.IO) {
                        val buffer = ProxyStats.obtain64k()
                        val packet = java.net.DatagramPacket(buffer, buffer.size)
                        try {
                            while (isActive) {
                                packet.setData(buffer)
                                udpSocket.receive(packet)
                                clientUdpAddress = packet.address
                                clientUdpPort = packet.port
                                
                                val data = packet.data
                                val len = packet.length
                                if (len < 10) continue
                                
                                // Parse SOCKS5 UDP header
                                val frag = data[2].toInt()
                                if (frag != 0) continue // Fragmented UDP not supported
                                
                                val pAtyp = data[3].toInt()
                                var headerLen = 4
                                var targetHost = ""
                                when (pAtyp) {
                                    1 -> {
                                        headerLen += 4
                                        val ipBytes = data.copyOfRange(4, 8)
                                        targetHost = InetAddress.getByAddress(ipBytes).hostAddress ?: ""
                                    }
                                    3 -> {
                                        val dlen = data[4].toInt() and 0xFF
                                        headerLen += 1 + dlen
                                        targetHost = String(data, 5, dlen)
                                    }
                                    4 -> {
                                        headerLen += 16
                                        val ipBytes = data.copyOfRange(4, 20)
                                        targetHost = InetAddress.getByAddress(ipBytes).hostAddress ?: ""
                                    }
                                }
                                val targetPortNum = ((data[headerLen].toInt() and 0xFF) shl 8) or (data[headerLen + 1].toInt() and 0xFF)
                                headerLen += 2
                                
                                val payload = data.copyOfRange(headerLen, len)
                                
                                if (targetPortNum == 53) {
                                    // Handle DNS query locally
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
                                                udpSocket.send(java.net.DatagramPacket(responseBytes, offset, packet.address, packet.port))
                                            }
                                        }
                                    }
                                } else {
                                    // General UDP Forwarding - using shared resolver with packet queuing
                                    val resolved = RobustResolver.getCached(targetHost)
                                    if (resolved != null && resolved.isNotEmpty()) {
                                        udpOutChannel.trySend(java.net.DatagramPacket(payload, payload.size, resolved.first(), targetPortNum) to targetHost)
                                    } else {
                                        // Queue packet and resolve in background
                                        launch(Dispatchers.IO) {
                                            try {
                                                val res = RobustResolver.resolve(targetHost, vpnService)
                                                if (res.isNotEmpty()) {
                                                    udpOutChannel.trySend(java.net.DatagramPacket(payload, payload.size, res.first(), targetPortNum) to targetHost)
                                                }
                                            } catch (e: Exception) {}
                                        }
                                    }
                                }
                            }
                        } catch (e: Exception) {
                        } finally {
                            ProxyStats.release64k(buffer)
                            udpOutChannel.close()
                            try { udpSocket.close() } catch (e: Exception) {}
                        }
                    }
                    
                    // Keep TCP connection alive, if it closes, UDP associate terminates
                    try {
                        input.read() // block until client closes
                    } finally {
                        udpSocket.close()
                        outSocket.close()
                        client.close()
                    }
                }
                return
            }
            val host = when (atyp) {
                1 -> { // IPv4
                    val addr = ByteArray(4)
                    readExactly(input, addr, 0, 4)
                    InetAddress.getByAddress(addr).hostAddress
                }
                3 -> { // Domain name
                    val len = input.read()
                    if (len == -1) throw IOException("EOF")
                    val addr = ByteArray(len)
                    readExactly(input, addr, 0, len)
                    String(addr)
                }
                4 -> { // IPv6
                    val addr = ByteArray(16)
                    readExactly(input, addr, 0, 16)
                    InetAddress.getByAddress(addr).hostAddress
                }
                else -> {
                    client.close()
                    return
                }
            }
            val portBytes = ByteArray(2)
            readExactly(input, portBytes, 0, 2)
            val targetPort = ((portBytes[0].toInt() and 0xff) shl 8) or (portBytes[1].toInt() and 0xff)
            
            // DNS Resolution with fallback
            val ips = try {
                RobustResolver.resolve(host, vpnService)
            } catch (e: Exception) {
                emptyList<InetAddress>()
            }
            
            if (ips.isEmpty()) {
                output.write(byteArrayOf(5, 4, 0, 1, 0, 0, 0, 0, 0, 0)) // Host unreachable
                output.flush()
                return
            }
            
            val targetIp = ips.first()
            ProxyStats.addTraffic(host)

            // Parallel connect racing for better reliability and speed
            targetSocket = try {
                withTimeout(15000) {
                    val channel = kotlinx.coroutines.channels.Channel<Socket>(ips.size)
                    val errors = java.util.concurrent.atomic.AtomicInteger(0)
                    val numJobs = minOf(ips.size, 3)
                    
                    val jobs = ips.take(3).map { ip ->
                        launch(Dispatchers.IO) {
                            val s = Socket()
                            s.tcpNoDelay = true
                            s.keepAlive = true
                            vpnService.protect(s)
                            try {
                                s.connect(InetSocketAddress(ip, targetPort), 10000)
                                channel.trySend(s)
                            } catch (e: Exception) {
                                try { s.close() } catch (e2: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e2.message}") }
                                if (errors.incrementAndGet() == numJobs) {
                                    channel.close()
                                }
                            }
                        }
                    }
                    
                    val winner = try {
                        channel.receive()
                    } catch (e: kotlinx.coroutines.channels.ClosedReceiveChannelException) {
                        throw Exception("All connection attempts failed")
                    }
                    
                    jobs.forEach { it.cancel() }
                    
                    // Cleanup any other sockets that might have succeeded
                    while (true) {
                        val s = channel.tryReceive().getOrNull() ?: break
                        if (s !== winner) try { s.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                    }
                    
                    winner
                }
            } catch (e: Exception) {
                Log.e("PinkProxy", "Failed to connect to $host: ${e.message}")
                output.write(byteArrayOf(5, 1, 0, 1, 0, 0, 0, 0, 0, 0))
                output.flush()
                return
            }

            // Success response
            output.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            output.flush()
            
            client.soTimeout = 0 // Remove timeout for the tunneled connection
            targetSocket.soTimeout = 0

            // Tunneling with bypass
            val targetInput = targetSocket!!.getInputStream()
            val targetOutput = targetSocket!!.getOutputStream()

            val strategy = BypassConfig.getBestStrategyForHost(host)
            val config = BypassConfig.getSessionConfig(host, strategy, BypassConfig.currentRttMs.value)

            try {
                coroutineScope {
                    launch {
                        val buffer = ProxyStats.obtain16k()
                        var firstPacket = true
                        try {
                            var len = 0
                            while (isActive) {
                                len = input.read(buffer)
                                if (len == -1) break
                                
                                if (firstPacket) {
                                    try {
                                        BypassConfig.applyBypass(targetSocket!!, targetOutput, buffer, len, config, host)
                                    } catch (e: Exception) {
                                        BypassConfig.recordFailure(strategy, host)
                                        throw e
                                    }
                                    firstPacket = false
                                } else {
                                    targetOutput.write(buffer, 0, len)
                                    targetOutput.flush()
                                }
                                ProxyStats.updateBytes(len.toLong())
                            }
                        } catch (e: Exception) {
                            BypassConfig.TrafficShaper.recordError()
                            // Expected on socket close
                        } finally {
                            ProxyStats.release16k(buffer)
                            try { targetSocket?.shutdownOutput() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                            try { client.shutdownInput() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                        }
                    }

                    launch {
                        val buffer = ProxyStats.obtain16k()
                        var firstResponse = true
                        val startTime = System.currentTimeMillis()
                        try {
                            var len = 0
                            while (isActive) {
                                len = targetInput.read(buffer)
                                if (len == -1) break
                                
                                if (firstResponse) {
                                    BypassConfig.recordSuccess(strategy, System.currentTimeMillis() - startTime, host)
                                    firstResponse = false
                                }
                                
                                // Adaptive chunking based on congestion window
                                val cwnd = (ProxyStats.congestionWindow.value * 1024).coerceAtLeast(1024)
                                var sent = 0
                                while (sent < len) {
                                    val toSend = (len - sent).coerceAtMost(cwnd)
                                    output.write(buffer, sent, toSend)
                                    output.flush()
                                    sent += toSend
                                    if (sent < len) delay(1) 
                                }
                                
                                ProxyStats.updateBytes(len.toLong())
                            }
                        } catch (e: Exception) {
                            BypassConfig.TrafficShaper.recordError()
                            // Expected on socket close
                        } finally {
                            ProxyStats.release16k(buffer)
                            try { client.shutdownOutput() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                            try { targetSocket.shutdownInput() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                        }
                    }
                }
            } catch (e: Exception) {
                Log.v("PinkProxy", "Relay terminated for $host: ${e.message}")
            }
        } catch (e: Exception) {
            Log.v("PinkProxy", "Client handling error: ${e.message}")
        } finally {
            try { targetSocket?.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
            try { client.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
            ProxyStats.updateConnections(-1)
        }
    }

    private suspend fun sendUdpPacket(socket: java.net.DatagramSocket, payload: ByteArray, targetInet: java.net.InetAddress, targetPort: Int, targetHost: String = "") {
        val outPacket = java.net.DatagramPacket(payload, payload.size, targetInet, targetPort)
        val strategy = BypassConfig.getBestStrategyForHost(if (targetHost.isNotEmpty()) targetHost else targetInet.hostAddress)
        
        val isQuic = targetPort == 443 && payload.isNotEmpty() && (payload[0].toInt() and 0xC0) == 0xC0
        
        if (BypassConfig.blockQuic && isQuic) {
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
                    val fakeQuicPacket = java.net.DatagramPacket(fakeQuic, fakeQuic.size, targetInet, targetPort)
                    TtlHelper.setUdpTtl(socket, 5, targetInet is java.net.Inet6Address)
                    socket.send(fakeQuicPacket)
                    delay(3)
                    TtlHelper.setUdpTtl(socket, 64, targetInet is java.net.Inet6Address)
                    socket.send(outPacket)
                }
                BypassStrategy.QUIC_RST_SKEW -> {
                    val rstPayload = FakePacketHelper.buildFakeUdpPacket(20) // Simulated QUIC Reset
                    val rstPacket = java.net.DatagramPacket(rstPayload, rstPayload.size, targetInet, targetPort)
                    TtlHelper.setUdpTtl(socket, 3, targetInet is java.net.Inet6Address)
                    socket.send(rstPacket)
                    delay(2)
                    TtlHelper.setUdpTtl(socket, 64, targetInet is java.net.Inet6Address)
                    socket.send(outPacket)
                }
                BypassStrategy.QUIC_VERSION_NEGOTIATION_SKEW -> {
                    val verPayload = ByteArray(100) { (it % 255).toByte() }
                    verPayload[0] = 0x80.toByte() // Long header
                    verPayload[1] = 0; verPayload[2] = 0; verPayload[3] = 0; verPayload[4] = 0 // Version Negotiation
                    val verPacket = java.net.DatagramPacket(verPayload, verPayload.size, targetInet, targetPort)
                    TtlHelper.setUdpTtl(socket, 3, targetInet is java.net.Inet6Address)
                    socket.send(verPacket)
                    delay(5)
                    TtlHelper.setUdpTtl(socket, 64, targetInet is java.net.Inet6Address)
                    socket.send(outPacket)
                }
                else -> {
                    // Default QUIC obfuscation
                    val fakeQuic = FakePacketHelper.buildQuicInitial()
                    val fakeQuicPacket = java.net.DatagramPacket(fakeQuic, fakeQuic.size, targetInet, targetPort)
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
                    val noisePacket = java.net.DatagramPacket(noise, noise.size, targetInet, targetPort)
                    TtlHelper.setUdpTtl(socket, 4, targetInet is java.net.Inet6Address)
                    socket.send(noisePacket)
                    delay(2)
                    TtlHelper.setUdpTtl(socket, 64, targetInet is java.net.Inet6Address)
                    socket.send(outPacket)
                }
                else -> {
                    // Default DNS Obfuscation
                    val noise = FakePacketHelper.buildQuicInitial() // Confuse DPI with QUIC on port 53
                    val noisePacket = java.net.DatagramPacket(noise, noise.size, targetInet, targetPort)
                    TtlHelper.setUdpTtl(socket, 5, targetInet is java.net.Inet6Address)
                    socket.send(noisePacket)
                    delay(3)
                    TtlHelper.setUdpTtl(socket, 64, targetInet is java.net.Inet6Address)
                    socket.send(outPacket)
                }
            }
        } else {
            // General UDP Obfuscation
            val noise = FakePacketHelper.buildFakeUdpPacket(java.util.concurrent.ThreadLocalRandom.current().nextInt(30, 150))
            val noisePacket = java.net.DatagramPacket(noise, noise.size, targetInet, targetPort)
            TtlHelper.setUdpTtl(socket, 5, targetInet is java.net.Inet6Address)
            socket.send(noisePacket)
            delay(3)
            TtlHelper.setUdpTtl(socket, 64, targetInet is java.net.Inet6Address)
            socket.send(outPacket)
        }
    }
}
