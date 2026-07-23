                // Open DatagramSocket to receive SOCKS5 UDP packets
                val udpSocket = java.net.DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
                val localPort = udpSocket.localPort
                
                // One outgoing socket for the entire UDP associate session
                val outSocket = java.net.DatagramSocket()
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
                
                coroutineScope {
                    // Receive from Target, forward to SOCKS5 Client
                    launch(Dispatchers.IO) {
                        try {
                            val buffer = ByteArray(65535)
                            while (isActive) {
                                val packet = java.net.DatagramPacket(buffer, buffer.size)
                                outSocket.receive(packet)
                                if (clientUdpAddress != null) {
                                    val outBuffer = java.io.ByteArrayOutputStream()
                                    outBuffer.write(0) // RSV
                                    outBuffer.write(0) // RSV
                                    outBuffer.write(0) // FRAG
                                    
                                    val addrBytes = packet.address.address
                                    if (addrBytes.size == 4) {
                                        outBuffer.write(1)
                                        outBuffer.write(addrBytes)
                                    } else {
                                        outBuffer.write(4)
                                        outBuffer.write(addrBytes)
                                    }
                                    outBuffer.write(packet.port shr 8)
                                    outBuffer.write(packet.port and 0xFF)
                                    outBuffer.write(packet.data, packet.offset, packet.length)
                                    
                                    val respBytes = outBuffer.toByteArray()
                                    udpSocket.send(java.net.DatagramPacket(respBytes, respBytes.size, clientUdpAddress, clientUdpPort))
                                }
                            }
                        } catch (e: Exception) {
                            // Ignored
                        }
                    }

                    // Receive from SOCKS5 Client, forward to Target
                    launch(Dispatchers.IO) {
                        try {
                            val buffer = ByteArray(65535)
                            while (isActive) {
                                val packet = java.net.DatagramPacket(buffer, buffer.size)
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
                                                
                                                val outBuffer = java.io.ByteArrayOutputStream()
                                                outBuffer.write(0); outBuffer.write(0); outBuffer.write(0)
                                                outBuffer.write(pAtyp)
                                                if (pAtyp == 1) outBuffer.write(data, 4, 4)
                                                else if (pAtyp == 3) { outBuffer.write(data[4].toInt()); outBuffer.write(data, 5, data[4].toInt() and 0xFF) }
                                                else if (pAtyp == 4) outBuffer.write(data, 4, 16)
                                                outBuffer.write(targetPortNum shr 8); outBuffer.write(targetPortNum and 0xFF)
                                                outBuffer.write(dnsReply)
                                                
                                                val responseBytes = outBuffer.toByteArray()
                                                udpSocket.send(java.net.DatagramPacket(responseBytes, responseBytes.size, packet.address, packet.port))
                                            }
                                        }
                                    }
                                } else {
                                    // General UDP Forwarding
                                    launch(Dispatchers.IO) {
                                        var targetIpStr = targetHost
                                        if (!RobustResolver.isIpAddress(targetHost)) {
                                            val resolved = RobustResolver.resolve(targetHost, vpnService)
                                            if (resolved.isNotEmpty()) {
                                                targetIpStr = resolved.first().hostAddress ?: targetHost
                                            }
                                        }
                                        try {
                                            val targetInet = InetAddress.getByName(targetIpStr)
                                            val outPacket = java.net.DatagramPacket(payload, payload.size, targetInet, targetPortNum)
                                            
                                            val strategy = BypassConfig.strategy.value
                                            if (strategy == BypassStrategy.UDP_NOISE) {
                                                val noise = FakePacketHelper.buildFakeUdpPacket(java.util.concurrent.ThreadLocalRandom.current().nextInt(50, 150))
                                                val noisePacket = java.net.DatagramPacket(noise, noise.size, targetInet, targetPortNum)
                                                TtlHelper.setUdpTtl(outSocket, 5)
                                                outSocket.send(noisePacket)
                                                delay(5)
                                                TtlHelper.setUdpTtl(outSocket, 64)
                                                outSocket.send(outPacket)
                                            } else if (strategy == BypassStrategy.UDP_XOR_OBFUSCATE) {
                                                val xorPayload = payload.copyOf()
                                                val mask = java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 255).toByte()
                                                for (i in xorPayload.indices) xorPayload[i] = (xorPayload[i].toInt() xor mask.toInt()).toByte()
                                                val noisePacket = java.net.DatagramPacket(xorPayload, xorPayload.size, targetInet, targetPortNum)
                                                TtlHelper.setUdpTtl(outSocket, 5)
                                                outSocket.send(noisePacket)
                                                delay(5)
                                                TtlHelper.setUdpTtl(outSocket, 64)
                                                outSocket.send(outPacket)
                                            } else if (strategy == BypassStrategy.DNS_OVER_QUIC_SIM && targetPortNum == 53) {
                                                val quicSim = FakePacketHelper.buildQuicInitial()
                                                val quicPacket = java.net.DatagramPacket(quicSim, quicSim.size, targetInet, targetPortNum)
                                                TtlHelper.setUdpTtl(outSocket, 5)
                                                outSocket.send(quicPacket)
                                                delay(5)
                                                TtlHelper.setUdpTtl(outSocket, 64)
                                                outSocket.send(outPacket)
                                            } else if (targetPortNum == 443 && payload.isNotEmpty() && (payload[0].toInt() and 0xC0) == 0xC0 && (strategy == BypassStrategy.QUIC_RANDOM_CID || strategy == BypassStrategy.CHAOS)) {
                                                val fakeQuic = FakePacketHelper.buildQuicInitial()
                                                val fakeQuicPacket = java.net.DatagramPacket(fakeQuic, fakeQuic.size, targetInet, targetPortNum)
                                                TtlHelper.setUdpTtl(outSocket, 5)
                                                outSocket.send(fakeQuicPacket)
                                                delay(5)
                                                TtlHelper.setUdpTtl(outSocket, 64)
                                                outSocket.send(outPacket)
                                            } else {
                                                outSocket.send(outPacket)
                                            }
                                        } catch (e: Exception) {
                                            // Ignored
                                        }
                                    }
                                }
                            }
                        } catch (e: Exception) {
                            // Ignored
                        } finally {
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
