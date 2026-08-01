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
    private val scope = CoroutineScope(ProxyDispatcher.io + SupervisorJob())
    private val isRunning = AtomicBoolean(false)
    
    private var lastIntelligenceUpdate = 0L
    private const val UPDATE_INTERVAL_MS = 60_000L // 1 minute
    
    fun start() {
        if (isRunning.getAndSet(true)) return
        
        scope.launch {
            while (isActive) {
                try {
                    performDeepAnalysis()
                    // Periodically perform light probes if traffic is low to keep fingerprint fresh
                    if (ProxyStats.activeConnections.value == 0) {
                        performLightBackgroundScan()
                    }
                } catch (e: Throwable) {
                    Log.e("CensorshipExpert", "Analysis loop error", e)
                }
                delay(UPDATE_INTERVAL_MS)
            }
        }
        
        // Listen to global DPI events to trigger immediate reactions
        scope.launch {
            ProxyStats.censorshipIntensity.collect { intensity ->
                if (intensity > 90) {
                    onExtremeCensorshipDetected()
                }
            }
        }
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
                    } catch (e: Throwable) {}
                }
            }.forEach { it.join() }
        }
        
        // Proactive Strategy Evaluation: Test a few strategies to see what's winning
        if (intensity > 40 && ProxyStats.getSuccessRate() < 70) {
            evaluateBestStrategies()
        }
    }

    private suspend fun evaluateBestStrategies() {
        Log.i("CensorshipExpert", "Evaluating optimal strategies proactively...")
        val testHost = "www.google.com"
        val testPort = 443
        val strategiesToTest = listOf(
            BypassStrategy.SNI_SPLIT,
            BypassStrategy.TCP_OOB_DESYNC,
            BypassStrategy.BYEBYEDPI_HYBRID,
            BypassStrategy.TCP_SEGMENT_OVERLAP,
            BypassStrategy.ECH_GREASE,
            BypassStrategy.TLS_SNI_SKEW
        )
        
        coroutineScope {
            strategiesToTest.forEach { strat ->
                launch {
                    val start = System.currentTimeMillis()
                    val socket = Socket()
                    try {
                        BypassConfig.activeVpnService?.protect(socket)
                        socket.soTimeout = 5000
                        val ips = RobustResolver.resolve(testHost)
                        if (ips.isNotEmpty()) {
                            val config = BypassConfig.getSessionConfig(testHost, strat, 100)
                            socket.connect(InetSocketAddress(ips.random(), testPort), 3000)
                            // Simulate a tiny part of handshake to see if it's reset
                            val hello = FakePacketHelper.buildChromeHello(testHost)
                            BypassConfig.applyBypass(socket, socket.getOutputStream(), hello, hello.size, config, testHost)
                            
                            val rtt = System.currentTimeMillis() - start
                            DpiEngine.recordResult(strat, true, HostCategory.OTHER, latencyMs = rtt)
                        }
                    } catch (e: Throwable) {
                        DpiEngine.recordResult(strat, false, HostCategory.OTHER)
                    } finally {
                        try { socket.close() } catch (e: Throwable) {}
                    }
                }
                delay(500) // Staggered tests
            }
        }
    }

    private fun performDeepAnalysis() {
        val now = System.currentTimeMillis()
        if (now - lastIntelligenceUpdate < 15000) return
        lastIntelligenceUpdate = now
        
        val fingerprint = DpiEngine.getCensorshipFingerprint()
        val successRate = ProxyStats.getSuccessRate()
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
        
        // 4. Panic Mode Prediction (Early Warning System)
        if (successRate < 45 && fingerprint.intensity > 70) {
            if (!BypassConfig.isPanicModeFlow.value) {
                Log.w("CensorshipExpert", "Predictive Panic Mode: Triggering pre-emptive defense")
                BypassConfig.setPanicMode(true)
            }
        }
    }

    private fun tuneMtu(fingerprint: DpiEngine.CensorshipFingerprint, stability: Int) {
        val currentMtu = BypassConfig.currentMtu.value
        var targetMtu = currentMtu
        
        if (fingerprint.timeoutRate > 0.5 || fingerprint.stallRate > 0.4 || stability < 40) {
            targetMtu = (currentMtu - 64).coerceAtLeast(1000)
        } else if (stability > 90 && successRateAbove(85) && currentMtu < 1400) {
            targetMtu = (currentMtu + 32).coerceAtMost(1400)
        }
        
        if (targetMtu != currentMtu) {
            BypassConfig.setMtu(targetMtu)
            Log.i("CensorshipExpert", "Adaptive MTU adjusted to $targetMtu")
        }
    }

    private fun optimizeGlobalStrategies(fingerprint: DpiEngine.CensorshipFingerprint, successRate: Int) {
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
                } catch (e: Throwable) {}
            }
        }
    }

    private fun onExtremeCensorshipDetected() {
        Log.e("CensorshipExpert", "EXTREME CENSORSHIP DETECTED! Deploying maximum evasion patterns.")
        BypassConfig.setPanicMode(true)
        BypassConfig.frag1 = 1
        BypassConfig.delay1 = 150
        
        // Clear all blacklists to allow fresh evaluation under extreme conditions
        DpiEngine.clearCircuitBreakers()
        
        // Boost nuclear strategies
        DpiEngine.recordResult(BypassStrategy.TCP_COMBINED_NUCLEAR, true, HostCategory.OTHER)
        DpiEngine.recordResult(BypassStrategy.UDP_COMBINED_NUCLEAR, true, HostCategory.OTHER)
    }

    private fun successRateAbove(threshold: Int): Boolean {
        return ProxyStats.getSuccessRate() > threshold
    }
}
