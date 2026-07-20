with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

import re

socks5_handler = """
    private suspend fun handleSocks5(client: Socket, initialBuffer: ByteArray, initialRead: Int, clientOut: OutputStream, clientIn: InputStream) {
        // Step 1: Initial greeting already read in initialBuffer
        // Send NO AUTH (0x05, 0x00)
        clientOut.write(byteArrayOf(0x05, 0x00))
        clientOut.flush()
        
        // Step 2: Read request
        val reqBuf = ByteArray(512)
        val read = clientIn.read(reqBuf)
        if (read < 4) return
        
        if (reqBuf[0] != 0x05.toByte() || reqBuf[1] != 0x01.toByte()) { // Only support CONNECT for now
            // Command not supported
            clientOut.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0))
            return
        }
        
        var host = ""
        val atyp = reqBuf[3].toInt()
        var pos = 4
        
        when (atyp) {
            0x01 -> { // IPv4
                host = "${reqBuf[4].toUByte()}.${reqBuf[5].toUByte()}.${reqBuf[6].toUByte()}.${reqBuf[7].toUByte()}"
                pos = 8
            }
            0x03 -> { // Domain
                val len = reqBuf[4].toInt() and 0xFF
                host = String(reqBuf, 5, len, Charsets.UTF_8)
                pos = 5 + len
            }
            0x04 -> { // IPv6
                // Simplified IPv6 representation, assuming RobustResolver handles it if needed
                host = ""
                pos = 20
            }
        }
        
        if (host.isEmpty() || pos + 1 >= read) {
            clientOut.write(byteArrayOf(0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0))
            return
        }
        
        val port = ((reqBuf[pos].toInt() and 0xFF) shl 8) or (reqBuf[pos+1].toInt() and 0xFF)
        
        val strategy = BypassConfig.resolveStrategyForHost(host); val config = BypassConfig.getSessionConfig(host, strategy, 100L)
        var target: Socket? = null
        var connected = false
        try {
            val ips = RobustResolver.resolve(host, vpnService); if (ips.isEmpty()) throw Exception("DNS Failed")
            for (ip in ips) {
                val sock = Socket()
                vpnService.protect(sock)
                try {
                    sock.connect(InetSocketAddress(ip, port), 2500)
                    sock.soTimeout = 30000
                    val osTtl = if (java.util.concurrent.ThreadLocalRandom.current().nextDouble() > 0.5) java.util.concurrent.ThreadLocalRandom.current().nextInt(60, 65) else java.util.concurrent.ThreadLocalRandom.current().nextInt(120, 129)
                    TtlHelper.setTtl(sock, osTtl)
                    target = sock
                    connected = true
                    break
                } catch (e: Exception) {
                    try { sock.close() } catch (ex: Exception) {}
                }
            }
            
            if (!connected || target == null) {
                // Host unreachable
                clientOut.write(byteArrayOf(0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0))
                return
            }
            
            // Success reply
            val reply = byteArrayOf(0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0) // bind address dummy
            clientOut.write(reply)
            clientOut.flush()
            
            val targetOut = target.getOutputStream()
            val targetIn = target.getInputStream()
            
            // Check if we need to send initial fake client hello or if it's raw
            // SOCKS5 doesn't have an initial client hello in the buffer, it's a pure transparent TCP stream from now on.
            // But we can apply traffic shaping!
            
            client.soTimeout = 90000
            target.soTimeout = 90000
            
            coroutineScope {
                val c2t = launch { proxyStream(clientIn, targetOut, { try { target?.close() } catch (e: Exception) {} }, host, false, strategy) }
                val t2c = launch { proxyStream(targetIn, clientOut, { try { client.close() } catch (e: Exception) {} }, host, true, strategy) }
                
                select<Unit> {
                    c2t.onJoin {}
                    t2c.onJoin {}
                }
                c2t.cancel(); t2c.cancel()
            }
            
        } catch (e: Exception) {
            try { clientOut.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0,0,0,0, 0,0)) } catch(ex: Exception) {}
        } finally {
            try { target?.close() } catch (e: Exception) {}
        }
    }
"""

content = re.sub(r'(private suspend fun handleHttps)', socks5_handler.strip() + '\n\n    \\1', content)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
