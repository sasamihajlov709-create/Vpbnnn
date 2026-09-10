with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DiagnosticManager.kt', 'r') as f:
    text = f.read()

replacement = '''
    suspend fun runFullDiagnostic(): HealthStatus = withContext(ProxyDispatcher.io) {
        val dnsSuccess = AtomicInteger(0)
        val tcpSuccess = AtomicInteger(0)
        
        val testDomains = listOf("google.com", "telegram.org", "github.com")
        
        var currentLevel = HealthLevel.L1_TUN_ALIVE
        
        // Check L2: Internal Proxy
        var socket: Socket? = null
        try {
            socket = Socket()
            socket.connect(InetSocketAddress("127.0.0.1", PinkVpnService.PROXY_PORT), 1000)
            socket.soTimeout = 2000
            
            // SOCKS5 Greeting
            val out = socket.getOutputStream()
            val input = socket.getInputStream()
            out.write(byteArrayOf(0x05, 0x01, 0x02))
            out.flush()
            val ack = ByteArray(2)
            if (input.read(ack) >= 2 && ack[1] == 0x02.toByte()) {
                // SOCKS5 Auth
                val secret = PinkVpnService.proxySecret
                val uBytes = secret.toByteArray()
                val authReq = ByteArray(1 + 1 + uBytes.size + 1 + uBytes.size)
                authReq[0] = 0x01
                authReq[1] = uBytes.size.toByte()
                System.arraycopy(uBytes, 0, authReq, 2, uBytes.size)
                authReq[2 + uBytes.size] = uBytes.size.toByte()
                System.arraycopy(uBytes, 0, authReq, 3 + uBytes.size, uBytes.size)
                out.write(authReq)
                out.flush()
                
                val authAck = ByteArray(2)
                if (input.read(authAck) >= 2 && authAck[1] == 0x00.toByte()) {
                    currentLevel = HealthLevel.L2_PROXY_ALIVE
                    
                    // SOCKS5 Connect to 1.1.1.1:80 (L6 Data Plane Verification)
                    out.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x00, 0x50))
                    out.flush()
                    val connAck = ByteArray(10)
                    if (input.read(connAck) >= 10 && connAck[1] == 0x00.toByte()) {
                        out.write("GET / HTTP/1.1\\r\\nHost: 1.1.1.1\\r\\nConnection: close\\r\\n\\r\\n".toByteArray())
                        out.flush()
                        val resp = ByteArray(16)
                        if (input.read(resp) > 0) {
                            currentLevel = HealthLevel.L6_APP_SUCCESS
                        } else {
                            currentLevel = HealthLevel.L4_TCP_REACHABLE
                        }
                    }
                }
            }
        } catch (e: Exception) {
            currentLevel = HealthLevel.L0_DEAD
        } finally {
            try { socket?.close() } catch (e: Exception) {}
        }
        
        // Parallel checks for Direct Upstream DNS/TCP to isolate issues
        val dnsJobs = testDomains.map { domain ->
            launch {
                val ips = RobustResolver.resolve(domain, BypassConfig.activeVpnService)
                if (ips.isNotEmpty()) dnsSuccess.incrementAndGet()
            }
        }
        dnsJobs.joinAll()
        
        if (dnsSuccess.get() > 0 && currentLevel < HealthLevel.L3_UPSTREAM_OK) {
            currentLevel = HealthLevel.L3_UPSTREAM_OK
        }
        
        val tcpJobs = testDomains.map { domain ->
            launch {
                val ips = RobustResolver.resolve(domain, BypassConfig.activeVpnService)
                if (ips.isNotEmpty()) {
                    var testSocket: Socket? = null
                    try {
                        testSocket = ProtectedSocketFactory.createProtectedSocket()
                        testSocket.connect(InetSocketAddress(ips.first(), 443), 2000)
                        tcpSuccess.incrementAndGet()
                    } catch (e: Exception) {
                    } finally {
                        try { testSocket?.close() } catch (e: Exception) {}
                    }
                }
            }
        }
        tcpJobs.joinAll()
        
        val intensity = ProxyStats.censorshipIntensity.value
        val bestStrat = BypassConfig.getStrategyForTransport(TransportType.TCP).value?.name ?: BypassStrategy.DIRECT.name
        
        val rec = when {
            currentLevel <= HealthLevel.L0_DEAD -> "Служба проксирования не отвечает. Выполняется перезапуск."
            currentLevel == HealthLevel.L2_PROXY_ALIVE && dnsSuccess.get() == 0 -> "DNS отравлен или заблокирован. Рекомендуется DoH Extreme."
            currentLevel == HealthLevel.L3_UPSTREAM_OK && tcpSuccess.get() == 0 -> "Критическая блокировка TCP. Попробуйте сменить сеть или включить режим 'Extreme'."
            currentLevel < HealthLevel.L6_APP_SUCCESS -> "Качество соединения нестабильно."
            intensity > 80 -> "Высокая цензура. Используется агрессивный обход."
            else -> "Соединение стабильно."
        }
        
        HealthStatus(
            level = currentLevel,
            dnsOk = dnsSuccess.get() > 0,
            tcpOk = tcpSuccess.get() > 0,
            censorshipIntensity = intensity,
            bestStrategy = bestStrat,
            recommendation = rec
        )
    }
'''

import re
pattern = re.compile(r'    suspend fun runFullDiagnostic\(\): HealthStatus = withContext\(ProxyDispatcher.io\) \{.*    \}', re.DOTALL)
text = pattern.sub(replacement.strip(), text)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DiagnosticManager.kt', 'w') as f:
    f.write(text)
