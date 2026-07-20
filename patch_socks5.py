import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

# Patch 1: handleSocks5
patch1_find = """        if (reqBuf[0] != 0x05.toByte() || reqBuf[1] != 0x01.toByte()) { // Only support CONNECT for now
            // Command not supported
            clientOut.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0))
            return
        }"""

patch1_repl = """        if (reqBuf[0] != 0x05.toByte() || (reqBuf[1] != 0x01.toByte() && reqBuf[1] != 0x03.toByte())) { 
            clientOut.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0))
            return
        }
        
        val isUdp = reqBuf[1] == 0x03.toByte()"""

if patch1_find in content:
    content = content.replace(patch1_find, patch1_repl)
else:
    print("Patch 1 failed to match.")

patch2_find = """        if (host.isEmpty() || pos + 1 >= read) {
            clientOut.write(byteArrayOf(0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0))
            return
        }"""

patch2_repl = """        if (!isUdp && (host.isEmpty() || pos + 1 >= read)) {
            clientOut.write(byteArrayOf(0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0))
            return
        }
        
        if (isUdp) {
            val p = port + 1
            clientOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, (p shr 8).toByte(), p.toByte()))
            clientOut.flush()
            
            try {
                val dummy = ByteArray(1024)
                while (clientIn.read(dummy) >= 0) {
                    kotlinx.coroutines.delay(2000)
                }
            } catch (e: Exception) {}
            return
        }"""

if patch2_find in content:
    content = content.replace(patch2_find, patch2_repl)
else:
    print("Patch 2 failed to match.")

# Patch 3: handleUdpPacket
patch3_find = """    private suspend fun handleUdpPacket(packet: java.net.DatagramPacket) {
        // This UDP relay on the proxy port (PROXY_PORT + 1) is currently a placeholder.
        // Direct UDP traffic from the TUN interface is handled by PinkVpnService directly.
        // We log metrics here for future SOCKS5 UDP relay support if needed.
        ProxyStats.recordDataReceived()
        ProxyStats.recordDataSent()
    }"""

patch3_repl = """    private suspend fun handleUdpPacket(packet: java.net.DatagramPacket) {
        val data = packet.data
        val len = packet.length
        if (len < 10) return
        if (data[0].toInt() != 0 || data[1].toInt() != 0) return // RSV
        val frag = data[2].toInt() // FRAG
        val atyp = data[3].toInt() // ATYP
        
        var dstHost = ""
        var dstPort = 0
        var headerLen = 0
        
        when (atyp) {
            1 -> { // IPv4
                if (len < 10) return
                dstHost = "${data[4].toUByte()}.${data[5].toUByte()}.${data[6].toUByte()}.${data[7].toUByte()}"
                dstPort = ((data[8].toInt() and 0xFF) shl 8) or (data[9].toInt() and 0xFF)
                headerLen = 10
            }
            3 -> { // Domain
                val dlen = data[4].toInt() and 0xFF
                if (len < 7 + dlen) return
                dstHost = String(data, 5, dlen)
                dstPort = ((data[5 + dlen].toInt() and 0xFF) shl 8) or (data[6 + dlen].toInt() and 0xFF)
                headerLen = 7 + dlen
            }
            else -> return // IPv6 not supported yet
        }
        
        val payload = data.copyOfRange(headerLen, len)
        val clientKey = "${packet.address.hostAddress}:${packet.port}"
        var session = udpSessions[clientKey]
        
        if (session == null || session.targetSocket.isClosed) {
            val sock = java.net.DatagramSocket()
            session = UdpSession(packet.address, packet.port, sock, System.currentTimeMillis())
            udpSessions[clientKey] = session
            
            serverScope.launch(Dispatchers.IO) {
                val buf = ByteArray(16384)
                while (isActive && !sock.isClosed) {
                    try {
                        val rxPacket = java.net.DatagramPacket(buf, buf.size)
                        sock.receive(rxPacket)
                        
                        val replyPort = rxPacket.port
                        val header = byteArrayOf(0, 0, 0, 1, 0, 0, 0, 0, (replyPort shr 8).toByte(), replyPort.toByte())
                        
                        val finalPayload = ByteArray(10 + rxPacket.length)
                        System.arraycopy(header, 0, finalPayload, 0, 10)
                        System.arraycopy(rxPacket.data, 0, finalPayload, 10, rxPacket.length)
                        
                        val outPacket = java.net.DatagramPacket(finalPayload, finalPayload.size, packet.address, packet.port)
                        udpSocket?.send(outPacket)
                        ProxyStats.recordDataReceived()
                    } catch(e: Exception) {
                        break
                    }
                }
            }
        }
        
        session.lastActivity = System.currentTimeMillis()
        try {
            val targetAddr = if (dstHost.matches(Regex("^[0-9.]+$"))) java.net.InetAddress.getByName(dstHost) else RobustResolver.resolve(dstHost, vpnService).firstOrNull()
            if (targetAddr != null) {
                val outPacket = java.net.DatagramPacket(payload, payload.size, targetAddr, dstPort)
                session.targetSocket.send(outPacket)
                ProxyStats.recordDataSent()
            }
        } catch(e: Exception) {}
    }"""

if patch3_find in content:
    content = content.replace(patch3_find, patch3_repl)
else:
    print("Patch 3 failed to match.")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)

