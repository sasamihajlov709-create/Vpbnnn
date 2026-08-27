import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt", "r") as f:
    content = f.read()

replacement = """
        val candidates = CandidateEngine.getEligibleCandidates(ctx, baseList).distinct().take(4)
        
        var bestCandidate: BypassStrategy? = null
        var bestLatency = Long.MAX_VALUE
        
        for (candidate in candidates) {
            val (success, latency) = testCandidate(ips, port, host, candidate, dummyClientHello, vpnService)
            if (success) {
                Log.i("ProactiveAutoTuner", "Discovered viable candidate strategy $candidate for $host proactively! (Latency: ${latency}ms)")
                if (latency < bestLatency) {
                    bestLatency = latency
                    bestCandidate = candidate
                }
            }
        }
        
        if (bestCandidate != null) {
            Log.i("ProactiveAutoTuner", "Selected optimal proactive candidate $bestCandidate for $host.")
        }
    }

    private suspend fun testCandidate(
        ips: List<InetAddress>,
        port: Int,
        host: String,
        strategy: BypassStrategy,
        payload: ByteArray,
        vpnService: VpnService?
    ): Pair<Boolean, Long> = withContext(ProxyDispatcher.io) {
"""

content = re.sub(
    r'        val candidates = CandidateEngine\.getEligibleCandidates.*?return@withContext false\n    \}',
    replacement.lstrip('\n') + """
        val rtt = BypassConfig.currentRttMs.value
        val config = BypassConfig.getSessionConfig(host, strategy, rtt, TransportType.TCP)
        
        try {
            val socket = HappyEyeballsConnector.connectHappyEyeballs(ips, port, vpnService, host)
            if (socket != null) {
                try {
                    val out = socket.getOutputStream()
                    val inStream = socket.getInputStream()
                    val startTime = System.currentTimeMillis()
                    
                    BypassApplier.applyBypass(socket, out, payload, payload.size, config, host)
                    
                    val buf = ByteArray(2048)
                    val read = inStream.read(buf)
                    
                    if (read > 0) {
                        val latency = System.currentTimeMillis() - startTime
                        val isTlsServerHello = read >= 5 && buf[0] == 0x16.toByte() && buf[1] == 0x03.toByte()
                        if (isTlsServerHello) {
                            try {
                                socket.soTimeout = 500
                                inStream.read(buf)
                            } catch (e: java.net.SocketTimeoutException) {
                            } catch (e: Exception) {
                                return@withContext Pair(false, 0L)
                            }
                            
                            DpiStrategySelector.recordResult(
                                strategy = strategy,
                                success = true,
                                transport = TransportType.TCP,
                                category = HostClassifier.classify(host),
                                host = host,
                                latencyMs = latency,
                                quality = ObservationQuality.TLS_RECORD_RECEIVED
                            )
                            return@withContext Pair(true, latency)
                        }
                    }
                } finally {
                    try { socket.close() } catch (e: Exception) {}
                }
            }
        } catch (e: Exception) {
        }
        
        DpiStrategySelector.recordResult(
            strategy = strategy,
            success = false,
            transport = TransportType.TCP,
            category = HostClassifier.classify(host),
            host = host,
            latencyMs = 0L,
            reason = FailureReason.TIMEOUT,
            quality = ObservationQuality.CONNECT_ONLY
        )
        return@withContext Pair(false, 0L)
    }""",
    content,
    flags=re.DOTALL
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt", "w") as f:
    f.write(content)

