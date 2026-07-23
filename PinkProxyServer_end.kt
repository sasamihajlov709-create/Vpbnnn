                                            
                                            val responseBytes = outBuffer.toByteArray()
                                            val responseDatagram = java.net.DatagramPacket(
                                                responseBytes,
                                                responseBytes.size,
                                                packet.address,
                                                packet.port
                                            )
                                            udpSocket.send(responseDatagram)
                                        } catch (e: Exception) {
                                            // Timeout or other error, UDP is stateless so we just drop
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

            // Connect to target
            val socket = Socket()
            targetSocket = socket
            socket.tcpNoDelay = true
            socket.keepAlive = true
            vpnService.protect(socket)
            try {
                withTimeout(10000) {
                    socket.connect(InetSocketAddress(targetIp, targetPort), 10000)
                }
            } catch (e: Exception) {
                Log.e("PinkProxy", "Failed to connect to $host ($targetIp): ${e.message}")
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
            val targetInput = socket.getInputStream()
            val targetOutput = socket.getOutputStream()

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
                                        BypassConfig.applyBypass(targetSocket, targetOutput, buffer, len, config, host)
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
                            // Expected on socket close
                        } finally {
                            ProxyStats.release16k(buffer)
                            try { targetSocket.shutdownOutput() } catch (e: Exception) {}
                            try { client.shutdownInput() } catch (e: Exception) {}
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
                            // Expected on socket close
                        } finally {
                            ProxyStats.release16k(buffer)
                            try { client.shutdownOutput() } catch (e: Exception) {}
                            try { targetSocket.shutdownInput() } catch (e: Exception) {}
                        }
                    }
                }
            } catch (e: Exception) {
                Log.v("PinkProxy", "Relay terminated for $host: ${e.message}")
            }
        } catch (e: Exception) {
            Log.v("PinkProxy", "Client handling error: ${e.message}")
        } finally {
            try { targetSocket?.close() } catch (e: Exception) {}
            try { client.close() } catch (e: Exception) {}
            ProxyStats.updateConnections(-1)
        }
    }
}
