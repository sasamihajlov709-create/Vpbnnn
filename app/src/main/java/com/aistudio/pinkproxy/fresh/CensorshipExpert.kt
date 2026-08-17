package com.aistudio.pinkproxy.fresh

import android.util.Log
import kotlinx.coroutines.*
import java.net.Socket
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The Central Intelligence Brain of PinkProxy.
 * Orchestrates DpiEngine, BypassConfig, and RobustResolver for maximum bypass effectiveness.
 */
object CensorshipExpert {
    private val scope = CoroutineScope(ProxyDispatcher.io + SupervisorJob() + ProxyDispatcher.globalHandler)
    private val isRunning = AtomicBoolean(false)
    
    private var lastIntelligenceUpdate = 0L
    private const val UPDATE_INTERVAL_MS = 60_000L // 1 minute
    
    private var analysisJob: Job? = null
    private var eventsJob: Job? = null
    
    fun start() {
        if (isRunning.getAndSet(true)) return
        
        analysisJob = scope.launch {
            while (isActive) {
                try {
                    performDeepAnalysis()
                    // Periodically perform light probes if traffic is low to keep fingerprint fresh
                    if (ProxyStats.activeConnections.value == 0) {
                        performLightBackgroundScan()
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.e("CensorshipExpert", "Analysis loop error: ${e.message}", e)
                }
                delay(UPDATE_INTERVAL_MS)
            }
        }
        
        // Listen to global DPI events to trigger immediate reactions
        eventsJob = scope.launch {
            var lastExtremeTriggerTime = 0L
            ProxyStats.censorshipIntensity.collect { intensity ->
                if (intensity > 90) {
                    val now = System.currentTimeMillis()
                    if (now - lastExtremeTriggerTime > 60_000) {
                        lastExtremeTriggerTime = now
                        onExtremeCensorshipDetected()
                    }
                }
            }
        }
    }

    fun stop() {
        if (!isRunning.getAndSet(false)) return
        analysisJob?.cancel()
        analysisJob = null
        eventsJob?.cancel()
        eventsJob = null
    }

    private suspend fun performLightBackgroundScan() {
        // Only scan if intensity is non-zero, to avoid unneeded traffic
        val intensity = ProxyStats.censorshipIntensity.value
        if (intensity < 5) return
        
        Log.d("CensorshipExpert", "Performing background network health scan...")
        val targets = listOf("dns.google", "one.one.one.one", "www.google.com")
        
        // Parallel health checks
        coroutineScope {
            targets.map { host ->
                launch {
                    try {
                        // Try UDP DNS with shadow - common test for DPI presence
                        val res = DnsProtocols.queryUdpDnsShadow(host, "8.8.8.8", BypassConfig.activeVpnService)
                        if (res.isEmpty()) {
                            ProxyStats.recordDpiEvent(DpiType.CONNECTION_TIMEOUT)
                        }
                    } catch (e: java.io.IOException) {
                        Log.v("CensorshipExpert", "Light scan query failed for $host: ${e.message}")
                    } catch (e: Exception) {
                        Log.v("CensorshipExpert", "Light scan unexpected error for $host: ${e.message}")
                    }
                }
            }.forEach { it.join() }
        }
        
        // Proactive Strategy Evaluation: Test a few strategies to see what's winning
        if (intensity > 40 && ProxyStats.successRate.value < 70) {
            evaluateBestStrategies()
        }
    }

    private suspend fun evaluateBestStrategies() {
        Log.i("CensorshipExpert", "Evaluating optimal strategies proactively with TLS ServerHello verification...")
        
        val probeTargets = listOf(
            Pair("www.google.com", HostCategory.OTHER),
            Pair("www.youtube.com", HostCategory.STREAMING),
            Pair("api.telegram.org", HostCategory.MESSENGER),
            Pair("chatgpt.com", HostCategory.AI)
        )
        
        val strategiesToTest = listOf(
            BypassStrategy.SNI_SPLIT,
            BypassStrategy.TCP_OOB_DESYNC,
            BypassStrategy.BYEBYEDPI_HYBRID,
            BypassStrategy.TCP_SEGMENT_OVERLAP,
            BypassStrategy.ECH_GREASE,
            BypassStrategy.TLS_SNI_SKEW,
            BypassStrategy.TCP_ZERO_WINDOW_STALL,
            BypassStrategy.TCP_ZERO_WINDOW_DESYNC,
            BypassStrategy.TCP_DATA_DESYNC,
            BypassStrategy.TCP_COMBINED_NUCLEAR,
            BypassStrategy.TCP_WINDOW_SIZE_SKEW
        ).filter { StrategyExecutionRegistry.isExecutorSupported(it, TransportType.TCP) }
        
        coroutineScope {
            probeTargets.forEach { (testHost, category) ->
                strategiesToTest.shuffled().take(5).forEach { strat ->
                    launch {
                        val start = System.currentTimeMillis()
                        var probeSocket: Socket? = null
                        try {
                            val ips = RobustResolver.resolve(testHost)
                            if (ips.isNotEmpty()) {
                                val targetAddr = ips.random()
                                val config = BypassConfig.getSessionConfig(testHost, strat, 100, transport = TransportType.TCP)
                                val hello = FakePacketHelper.buildRealisticTlsHello(testHost)
                                
                                probeSocket = Socket()
                                BypassConfig.activeVpnService?.protect(probeSocket)
                                probeSocket.soTimeout = 3500
                                probeSocket.connect(InetSocketAddress(targetAddr, 443), 2500)
                                
                                val executedStrategy = config.strategy
                                BypassConfig.applyBypass(probeSocket, probeSocket.getOutputStream(), hello, hello.size, config, testHost)
                                
                                // Real TLS Handshake Verification: Read first byte from server.
                                // TLS Record Handshake header starts with byte 0x16 (22)
                                val buffer = ByteArray(5)
                                var readBytes = 0
                                val readSuccess = withContext(Dispatchers.IO) {
                                    try {
                                        readBytes = probeSocket.getInputStream().read(buffer)
                                        readBytes > 0 && buffer[0] == 0x16.toByte()
                                    } catch (e: Exception) {
                                        false
                                    }
                                }
                                
                                val rtt = System.currentTimeMillis() - start
                                val success = probeSocket.isConnected && readSuccess
                                
                                DpiEngine.recordStrategyResult(
                                    host = testHost,
                                    strat = executedStrategy,
                                    success = success,
                                    latencyMs = if (success) rtt else 0,
                                    quality = if (success) ObservationQuality.HANDSHAKE_COMPLETE else ObservationQuality.CONNECT_ONLY,
                                    requestedStrategy = strat,
                                    effectiveStrategy = executedStrategy,
                                    transport = TransportType.TCP
                                )
                                if (success) {
                                    Log.d("CensorshipExpert", "Probe SUCCESS: $executedStrategy on $testHost ($category) RTT=${rtt}ms")
                                } else {
                                    Log.v("CensorshipExpert", "Probe FAIL: $executedStrategy on $testHost ($category) readBytes=$readBytes")
                                }
                            }
                        } catch (e: java.net.ConnectException) {
                            Log.v("CensorshipExpert", "Probe $strat connect failed on $testHost: ${e.message}")
                            DpiEngine.recordStrategyResult(host = testHost, strat = strat, success = false, reason = FailureReason.CONNECTION_REFUSED, transport = TransportType.TCP)
                        } catch (e: java.net.SocketTimeoutException) {
                            Log.v("CensorshipExpert", "Probe $strat timed out on $testHost")
                            DpiEngine.recordStrategyResult(host = testHost, strat = strat, success = false, reason = FailureReason.TIMEOUT, transport = TransportType.TCP)
                        } catch (e: Exception) {
                            Log.v("CensorshipExpert", "Probe $strat unexpected error on $testHost: ${e.message}")
                            DpiEngine.recordStrategyResult(host = testHost, strat = strat, success = false, reason = FailureReason.UNKNOWN, transport = TransportType.TCP)
                        } finally {
                            try { probeSocket?.close() } catch (e: java.io.IOException) {}
                        }
                    }
                    delay(150) // Staggered probes
                }
            }
        }
    }

    private fun performDeepAnalysis() {
        val now = System.currentTimeMillis()
        if (now - lastIntelligenceUpdate < 15000) return
        lastIntelligenceUpdate = now
        
        val fingerprint = DpiEngine.getCensorshipFingerprint()
        val successRate = ProxyStats.successRate.value
        val dnsPoisoningRate = ProxyStats.dpiEvents[DpiType.DNS_POISONING]?.toFloat() ?: 0f
        val stability = ProxyStats.stabilityScore.value
        
        Log.i("CensorshipExpert", "Deep Analysis: Success $successRate%, Intensity ${fingerprint.intensity}, RST Rate ${fingerprint.rstRate}")

        // 1. Adaptive MTU Tuning
        tuneMtu(fingerprint, stability)
        
        // 2. Global Strategy Family Optimization
        optimizeGlobalStrategies(fingerprint, successRate)
        
        // 3. DNS Resilience Hardening
        if (dnsPoisoningRate > 5 || fingerprint.sniBlockRate > 0.4) {
            hardenDns()
        }
        
        // 4. Probing Reaction: Check if we are being actively probed
        detectAndReactToProbing(fingerprint, successRate)

        // 5. CDN Warmup: If success rate is dropping, warm up common CDN paths
        if (successRate < 60 && ProxyStats.activeConnections.value > 0) {
            scope.launch { performCdnGhostingWarmup() }
        }
        
        // 6. Panic Mode Prediction (Early Warning System)
        if (successRate < 45 && fingerprint.intensity > 70) {
            if (!BypassConfig.isPanicModeFlow.value) {
                Log.w("CensorshipExpert", "Predictive Panic Mode: Triggering pre-emptive defense")
                BypassConfig.setPanicMode(true)
            }
        }
    }

    private fun detectAndReactToProbing(fingerprint: DpiAnalyzer.CensorshipFingerprint, successRate: Int) {
        // Active Probing detection: High RST rate combined with specific stall patterns
        if (fingerprint.rstRate > 0.35 || (fingerprint.stallRate > 0.4 && successRate < 50)) {
            Log.w("CensorshipExpert", "ACTIVE PROBING DETECTED. Forcing extreme desynchronization.")
            // Boost all desync and EXTREME strategies
            DpiEngine.boostStrategyFamily(StrategyFamily.TCP, null)
            DpiEngine.boostStrategyFamily(StrategyFamily.FRAGMENTATION, null)
            
            // Mark global state as "Probed" to influence DpiEngine's softmax selection
            ProxyStats.recordDpiEvent(DpiType.TCP_STALL) // Use as a trigger
        }
    }

    private suspend fun performCdnGhostingWarmup() {
        val cdnInnocentHosts = listOf(
            "ajax.googleapis.com", 
            "fonts.gstatic.com", 
            "cdnjs.cloudflare.com", 
            "s.ytimg.com",
            "static.xx.fbcdn.net"
        )
        val host = cdnInnocentHosts.random()
        Log.d("CensorshipExpert", "CDN Ghosting Warmup: $host")
        try {
            val ips = RobustResolver.resolve(host)
            if (ips.isNotEmpty()) {
                val s = Socket()
                BypassConfig.activeVpnService?.protect(s)
                s.soTimeout = 3000
                withContext(Dispatchers.IO) {
                    s.connect(InetSocketAddress(ips.random(), 443), 2000)
                    val out = s.getOutputStream()
                    val hello = FakePacketHelper.buildRealisticTlsHello(host)
                    // Use light bypass to look like a real browser
                    val config = BypassConfig.getSessionConfig(host, BypassStrategy.TLS_SNI_FRAGMENT, 50)
                    BypassConfig.applyBypass(s, out, hello, hello.size, config, host)
                    delay(java.util.concurrent.ThreadLocalRandom.current().nextLong(100, 500))
                    s.close()
                }
            }
        } catch (e: Throwable) {}
    }

    

    private fun tuneMtu(fingerprint: DpiAnalyzer.CensorshipFingerprint, stability: Int) {
        val currentMtu = BypassConfig.currentMtu.value
        var targetMtu = currentMtu
        val mtuErrors = ProxyStats.dpiEvents[DpiType.MTU_EXCEEDED] ?: 0
        
        if (mtuErrors > 2 || fingerprint.timeoutRate > 0.5 || fingerprint.stallRate > 0.4 || stability < 40) {
            // Aggressive reduction if specific MTU errors or high instability detected
            targetMtu = (currentMtu - 48).coerceAtLeast(1000)
            if (mtuErrors > 5) targetMtu = 1280 // Standard "safe" MTU for many networks
            ProxyStats.resetDpiEvent(DpiType.MTU_EXCEEDED)
        } else if (stability > 90 && successRateAbove(88) && currentMtu < 1420) {
            // Gradual increase for high performance
            targetMtu = (currentMtu + 16).coerceAtMost(1450)
        }
        
        if (targetMtu != currentMtu) {
            BypassConfig.setMtu(targetMtu)
            Log.i("CensorshipExpert", "Adaptive MTU intelligently tuned to $targetMtu (MTU Errors: $mtuErrors)")
        }
    }

    private fun optimizeGlobalStrategies(fingerprint: DpiAnalyzer.CensorshipFingerprint, successRate: Int) {
        // Boost strategy families based on the type of blocking detected
        when {
            fingerprint.rstRate > 0.3 -> {
                DpiEngine.boostStrategyFamily(StrategyFamily.TCP, null)
                DpiEngine.boostStrategyFamily(StrategyFamily.FRAGMENTATION, null)
            }
            fingerprint.sniBlockRate > 0.4 -> {
                DpiEngine.boostStrategyFamily(StrategyFamily.TLS, null)
                DpiEngine.boostStrategyFamily(StrategyFamily.FRAGMENTATION, null)
            }
            fingerprint.udpBlockRate > 0.6 -> {
                DpiEngine.boostStrategyFamily(StrategyFamily.UDP, null)
                DpiEngine.boostStrategyFamily(StrategyFamily.QUIC, null)
            }
        }
        
        // If everything is failing, rotate to a "Chaos" or "Combined" strategy
        if (successRate < 20 && ProxyStats.activeConnections.value > 5) {
            BypassConfig.rotateGlobalStrategy()
        }
    }

    private fun hardenDns() {
        Log.w("CensorshipExpert", "DNS Under Siege. Hardening DNS infrastructure.")
        RobustResolver.clearCache()
        DpiEngine.boostStrategyFamily(StrategyFamily.DNS, null)
        
        // Pro-actively pre-resolve critical domains using Nuclear methods
        scope.launch {
            val critical = listOf("dns.google", "cloudflare-dns.com", "api.telegram.org", "www.youtube.com")
            critical.forEach { host ->
                try {
                    RobustResolver.resolveDnsOverTcpOnly(host)
                } catch (e: java.net.UnknownHostException) {
                    Log.v("CensorshipExpert", "Harden DNS pre-resolve failed for $host")
                } catch (e: Exception) {
                    Log.v("CensorshipExpert", "Harden DNS unexpected error for $host: ${e.message}")
                }
            }
        }
    }

    private fun onExtremeCensorshipDetected() {
        Log.i("CensorshipExpert", "EXTREME CENSORSHIP DETECTED! Deploying maximum evasion patterns.")
        BypassConfig.setPanicMode(true)
        BypassConfig.frag1 = 1
        BypassConfig.delay1 = 150
        
        // Clear all blacklists to allow fresh evaluation under extreme conditions
        DpiEngine.clearCircuitBreakers()
    }

    private fun successRateAbove(threshold: Int): Boolean {
        return ProxyStats.successRate.value > threshold
    }
}
