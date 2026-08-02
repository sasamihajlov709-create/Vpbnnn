package com.aistudio.pinkproxy.fresh

import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.LinkedList
import java.util.Collections

object DpiEngine {
    private val scope = CoroutineScope(ProxyDispatcher.io + SupervisorJob())
    private val successHistory = ConcurrentHashMap<BypassStrategy, AtomicInteger>()
    private val failureHistory = ConcurrentHashMap<BypassStrategy, AtomicInteger>()
    
    private val _currentDpiLevel = MutableStateFlow(0)
    val currentDpiLevel = _currentDpiLevel.asStateFlow()

    private val strategyScores = ConcurrentHashMap<HostCategory, ConcurrentHashMap<BypassStrategy, AtomicInteger>>()
    private val strategyLatency = ConcurrentHashMap<BypassStrategy, java.util.concurrent.atomic.AtomicLong>()
    private val circuitBreakers = ConcurrentHashMap<BypassStrategy, Long>()
    private val consecutiveFailures = ConcurrentHashMap<BypassStrategy, AtomicInteger>()
    private val hostStrategyBlacklist = ConcurrentHashMap<String, ConcurrentHashMap<BypassStrategy, Long>>()
    
    private val rttHistory = ConcurrentHashMap<HostCategory, MutableList<Long>>()
    private val MAX_RTT_HISTORY = 10

    private var lastGlobalReset = System.currentTimeMillis()
    private var lastPanicTime = 0L
    private val eventHistory = ConcurrentHashMap<DpiType, AtomicInteger>()
    
    data class CensorshipFingerprint(
        val rstRate: Double,
        val sniBlockRate: Double,
        val udpBlockRate: Double,
        val timeoutRate: Double,
        val stallRate: Double,
        val jitter: Double,
        val intensity: Int
    )

    fun getCensorshipFingerprint(): CensorshipFingerprint {
        val total = eventHistory.values.sumOf { it.get() }.toDouble().coerceAtLeast(1.0)
        
        // Decay event history so fingerprint is recent
        if (total > 500) {
            eventHistory.forEach { (_, count) ->
                count.updateAndGet { (it * 0.9).toInt() }
            }
        }
        
        // Calculate global jitter from RTT history
        val allHistory = rttHistory.values.flatten()
        val jitter = if (allHistory.size > 2) {
            val diffs = allHistory.zipWithNext { a, b -> Math.abs(a - b) }
            diffs.average()
        } else 0.0

        return CensorshipFingerprint(
            rstRate = (eventHistory[DpiType.TCP_RESET]?.get() ?: 0) / total,
            sniBlockRate = (eventHistory[DpiType.TLS_SNI_BLOCK]?.get() ?: 0) / total,
            udpBlockRate = (eventHistory[DpiType.UDP_BLOCK]?.get() ?: 0) / total,
            timeoutRate = (eventHistory[DpiType.CONNECTION_TIMEOUT]?.get() ?: 0) / total,
            stallRate = ((eventHistory[DpiType.TCP_STALL]?.get() ?: 0) + (eventHistory[DpiType.SSL_STALL]?.get() ?: 0)) / total,
            jitter = jitter,
            intensity = ProxyStats.censorshipIntensity.value
        )
    }

    fun start(context: android.content.Context) {
        // Initialize scores
        HostCategory.entries.forEach { cat ->
            val catScores = ConcurrentHashMap<BypassStrategy, AtomicInteger>()
            BypassStrategy.entries.forEach { strat ->
                catScores[strat] = AtomicInteger(100) // Base score
            }
            strategyScores[cat] = catScores
        }
        
        initStrategyChains()
        loadScores(context)

        scope.launch {
            while (isActive) {
                delay(30000)
                try {
                    analyzeAndAdjust()
                    checkGlobalStall()
                } catch (e: Throwable) {
                    Log.e("DpiEngine", "Optimizer error", e)
                }
            }
        }
        
        // Auto-scan on first start or long time since last scan
        val prefs = context.getSharedPreferences("dpi_engine_state", android.content.Context.MODE_PRIVATE)
        val lastScan = prefs.getLong("last_scan_time", 0L)
        if (System.currentTimeMillis() - lastScan > 86400000L) { // Daily scan or first time
            performInitialScan(context)
        }
    }

    fun performQuickScan(context: android.content.Context) {
        scope.launch {
            Log.i("DpiEngine", "Starting QUICK automated censorship scan...")
            val targets = listOf("google.com", "telegram.org")
            val probes = listOf(
                BypassStrategy.TLS_SNI_FRAGMENT,
                BypassStrategy.SNI_SPLIT,
                BypassStrategy.TCP_RETRANS_FAKE
            )
            
            targets.forEach { host ->
                val resolved = try { RobustResolver.resolve(host) } catch (e: Throwable) { emptyList() }
                if (resolved.isNotEmpty()) {
                    val addr = resolved.first()
                    probes.forEach { strat ->
                        try {
                            withTimeoutOrNull(2500) {
                                val s = java.net.Socket()
                                try {
                                    s.connect(java.net.InetSocketAddress(addr, 443), 1200)
                                    val out = s.getOutputStream()
                                    val fake = FakePacketHelper.buildRealisticTlsHello(host)
                                    val config = BypassConfig.getSessionConfig(host, strat, 50)
                                    BypassConfig.applyBypass(s, out, fake, fake.size, config, host)
                                    s.soTimeout = 1200
                                    val i = s.getInputStream().read()
                                    if (i != -1) {
                                        recordResult(strat, true, HostClassifier.classify(host), latencyMs = 100, host = host)
                                    }
                                } catch (e: Throwable) {
                                } finally {
                                    try { s.close() } catch (e: Throwable) {}
                                }
                            }
                        } catch (e: Throwable) {}
                    }
                }
            }
            Log.i("DpiEngine", "Quick scan complete.")
        }
    }

    fun performInitialScan(context: android.content.Context) {
        scope.launch {
            Log.i("DpiEngine", "Starting automated censorship fingerprinting...")
            val targets = listOf("google.com", "youtube.com", "telegram.org")
            val probes = listOf(
                BypassStrategy.TCP_RETRANS_FAKE,
                BypassStrategy.TLS_SNI_FRAGMENT,
                BypassStrategy.SNI_SPLIT,
                BypassStrategy.TCP_SEGMENT_OVERLAP,
                BypassStrategy.ECH_GREASE,
                BypassStrategy.TCP_COMBINED_NUCLEAR
            )
            
            targets.forEach { host ->
                val resolved = try { RobustResolver.resolve(host) } catch (e: Throwable) { emptyList() }
                if (resolved.isNotEmpty()) {
                    val addr = resolved.first()
                    probes.forEach { strat ->
                        try {
                            val start = System.currentTimeMillis()
                            val ok = withTimeoutOrNull(3000) {
                                val s = java.net.Socket()
                                try {
                                    s.connect(java.net.InetSocketAddress(addr, 443), 1500)
                                    val out = s.getOutputStream()
                                    // Make a fake packet using the strategy
                                    val fake = FakePacketHelper.buildRealisticTlsHello(host)
                                    val config = BypassConfig.getSessionConfig(host, strat, 50)
                                    BypassConfig.applyBypass(s, out, fake, fake.size, config, host)
                                    // Wait for some data to see if we survived DPI
                                    s.soTimeout = 1500
                                    val i = s.getInputStream().read()
                                    i != -1
                                } catch (e: Throwable) {
                                    false
                                } finally {
                                    try { s.close() } catch (e: Throwable) {}
                                }
                            }
                            val latency = System.currentTimeMillis() - start
                            if (ok == true) {
                                recordResult(strat, true, HostClassifier.classify(host), latencyMs = latency)
                            } else {
                                recordResult(strat, false, HostClassifier.classify(host), reason = FailureReason.CONNECTION_REFUSED)
                            }
                        } catch (e: Throwable) {}
                        delay(200)
                    }
                }
            }
            
            context.getSharedPreferences("dpi_engine_state", android.content.Context.MODE_PRIVATE)
                .edit().putLong("last_scan_time", System.currentTimeMillis()).apply()
            Log.i("DpiEngine", "Initial scan complete. Intensity: ${ProxyStats.censorshipIntensity.value}")
        }
    }

    private fun checkGlobalStall() {
        val total = successHistory.values.sumOf { it.get() } + failureHistory.values.sumOf { it.get() }
        if (total > 20) {
            val rate = (successHistory.values.sumOf { it.get() }.toDouble() / total * 100)
            val fingerprint = getCensorshipFingerprint()
            
            if ((rate < 15 || fingerprint.timeoutRate > 0.8) && System.currentTimeMillis() - lastGlobalReset > 480_000) {
                Log.e("DpiEngine", "GLOBAL STALL DETECTED (Success rate $rate%, Timeout ${fingerprint.timeoutRate*100}%). Emergency fallback rotation.")
                ProxyStats.logRecovery("Global Connectivity Stall: Emergency Strategy Rotation Triggered")
                BypassConfig.rotateGlobalStrategy()
                lastGlobalReset = System.currentTimeMillis()
                
                // Nuclear reset if it's really bad
                if (rate < 5) resetEverything()
            }
        }
    }

    private fun resetEverything() {
        strategyScores.values.forEach { catScores ->
            catScores.values.forEach { it.set(100) }
        }
        circuitBreakers.clear()
        consecutiveFailures.clear()
        successHistory.clear()
        failureHistory.clear()
    }

    fun getBestExtremeStrategy(host: String? = null): BypassStrategy {
        val cat = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
        val extreme = strategyScores[cat]?.entries?.filter { it.key.group == StrategyGroup.EXTREME } ?: emptyList()
        if (extreme.isEmpty()) {
            return BypassStrategy.entries.filter { it.group == StrategyGroup.EXTREME }
                .maxByOrNull { getAverageScore(it) } ?: BypassStrategy.ZAPRET_EXTREME
        }
        return extreme.maxByOrNull { it.value.get() }?.key ?: BypassStrategy.ZAPRET_EXTREME
    }

    fun recordEvent(type: DpiType) {
        eventHistory.getOrPut(type) { AtomicInteger(0) }.incrementAndGet()
        
        // Adjust scores based on DPI type
        when (type) {
            DpiType.TLS_SNI_BLOCK -> {
                boostStrategyFamily(StrategyFamily.FRAGMENTATION, null)
                boostStrategyFamily(StrategyFamily.TLS, null)
            }
            DpiType.UDP_BLOCK -> boostStrategyFamily(StrategyFamily.UDP, null)
            DpiType.TCP_RESET -> {
                boostStrategyFamily(StrategyFamily.TCP, null)
                boostStrategyFamily(StrategyFamily.FRAGMENTATION, null)
            }
            DpiType.DNS_POISONING -> boostStrategyFamily(StrategyFamily.DNS, null)
            DpiType.HTTP_BLOCK -> boostStrategyFamily(StrategyFamily.HTTP, null)
            DpiType.TLS_HANDSHAKE_TIMEOUT -> {
                boostStrategyFamily(StrategyFamily.TLS, null)
                boostStrategyFamily(StrategyFamily.TIMING, null)
            }
            DpiType.CONNECTION_TIMEOUT -> {
                boostStrategyFamily(StrategyFamily.FRAGMENTATION, null)
                boostStrategyFamily(StrategyFamily.TCP, null)
            }
            DpiType.TCP_STALL, DpiType.SSL_STALL -> {
                boostStrategyFamily(StrategyFamily.FRAGMENTATION, null)
                boostStrategyFamily(StrategyFamily.TCP, null)
                boostStrategyFamily(StrategyFamily.TIMING, null)
                // When stalling, EXTREME strategies are usually needed to break the block
                BypassStrategy.entries.forEach { strat ->
                    if (strat.group == StrategyGroup.EXTREME) {
                        recordResult(strat, true, HostCategory.OTHER) // Soft boost
                    }
                }
            }
            else -> {}
        }
    }

    private val strategyMaturity = ConcurrentHashMap<BypassStrategy, AtomicInteger>()
    private val networkStrategyMemory = ConcurrentHashMap<String, ConcurrentHashMap<HostCategory, BypassStrategy>>()
    data class HostMemory(val strategy: BypassStrategy, val timestamp: Long)
    private val hostSpecificMemory = ConcurrentHashMap<String, HostMemory>()
    private val strategyChains = ConcurrentHashMap<BypassStrategy, BypassStrategy>()

    private fun initStrategyChains() {
        // Define fallback chains for automated recovery
        strategyChains[BypassStrategy.SNI_SPLIT] = BypassStrategy.TLS_SNI_FRAGMENT
        strategyChains[BypassStrategy.TLS_SNI_FRAGMENT] = BypassStrategy.TLS_APP_DATA_SPLIT
        strategyChains[BypassStrategy.TLS_APP_DATA_SPLIT] = BypassStrategy.BYEBYEDPI_HYBRID
        strategyChains[BypassStrategy.BYEBYEDPI_HYBRID] = BypassStrategy.TCP_SEGMENT_OVERLAP
        strategyChains[BypassStrategy.TCP_SEGMENT_OVERLAP] = BypassStrategy.TCP_DATA_DESYNC_OVERLAP
        strategyChains[BypassStrategy.TCP_DATA_DESYNC_OVERLAP] = BypassStrategy.TCP_TRIPLE_DESYNC
        strategyChains[BypassStrategy.TCP_TRIPLE_DESYNC] = BypassStrategy.TCP_FAKE_FIN
        strategyChains[BypassStrategy.TCP_FAKE_FIN] = BypassStrategy.TCP_COMBINED_NUCLEAR
        
        strategyChains[BypassStrategy.TCP_FOOL_DPI] = BypassStrategy.ZAPRET_EXTREME
        strategyChains[BypassStrategy.ZAPRET_EXTREME] = BypassStrategy.TCP_COMBINED_NUCLEAR
        
        strategyChains[BypassStrategy.WINDOW_SIZE_MANGLE] = BypassStrategy.TCP_WINDOW_SIZE_SKEW
        strategyChains[BypassStrategy.TCP_WINDOW_SIZE_SKEW] = BypassStrategy.TCP_WINDOW_CLAMPING
        strategyChains[BypassStrategy.TCP_WINDOW_CLAMPING] = BypassStrategy.TCP_ZERO_WINDOW_STALL
        strategyChains[BypassStrategy.TCP_ZERO_WINDOW_STALL] = BypassStrategy.TCP_ZERO_WINDOW_DESYNC
        
        strategyChains[BypassStrategy.TCP_REORDER_DESYNC] = BypassStrategy.TCP_OOB_DESYNC
        strategyChains[BypassStrategy.TCP_OOB_DESYNC] = BypassStrategy.TCP_OOB_SEGMENTATION
        strategyChains[BypassStrategy.TCP_OOB_SEGMENTATION] = BypassStrategy.TCP_DATA_DESYNC_OVERLAP
        
        strategyChains[BypassStrategy.UDP_NOISE_CHAOS] = BypassStrategy.UDP_BURST_CHAOS
        strategyChains[BypassStrategy.UDP_BURST_CHAOS] = BypassStrategy.UDP_COMBINED_NUCLEAR
    }

    fun getFallbackStrategy(failedStrategy: BypassStrategy): BypassStrategy? {
        return strategyChains[failedStrategy]
    }

    fun recordRtt(host: String, rtt: Long) {
        val cat = HostClassifier.classify(host)
        val history = rttHistory.getOrPut(cat) { Collections.synchronizedList(LinkedList()) }
        
        history.add(rtt)
        if (history.size > MAX_RTT_HISTORY) history.removeAt(0)
        
        // Detect throttling: if current RTT is > 2.5x the average of previous ones
        if (history.size >= 5) {
            val avg = history.take(history.size - 1).average()
            if (rtt > avg * 2.5 && rtt > 300) {
                Log.w("DpiEngine", "THROTTLING DETECTED for $cat (RTT: $rtt, Avg: $avg). Boosting strategy family.")
                boostStrategyFamily(StrategyFamily.ADAPTIVE, host)
                ProxyStats.logRecovery("Throttling detected for $cat. Adaptive boost applied.")
            }
        }
    }

    fun recordResult(strategy: BypassStrategy, success: Boolean, category: HostCategory = HostCategory.OTHER, reason: FailureReason? = null, latencyMs: Long = 0, host: String? = null) {
        if (success) {
            successHistory.getOrPut(strategy) { AtomicInteger(0) }.incrementAndGet()
            strategyMaturity.getOrPut(strategy) { AtomicInteger(0) }.incrementAndGet()
            
            strategyScores[category]?.get(strategy)?.let { score ->
                // Fast recovery for successful strategies
                val bonus = if (latencyMs in 1..300) 35 else 15
                score.addAndGet(bonus)
                if (score.get() > 3000) score.set(3000)
            }
            
            if (host != null) {
                hostStrategyBlacklist[host]?.remove(strategy)
                consecutiveFailuresByHost[host]?.set(0)
                
                // Host-specific learning
                hostSpecificMemory[host] = HostMemory(strategy, System.currentTimeMillis())
                
                // Store in network-specific memory
                val netType = BypassConfig.currentNetworkType.value.toString()
                val netMemory = networkStrategyMemory.getOrPut(netType) { ConcurrentHashMap() }
                
                // Only promote if it's consistently working
                if ((strategyMaturity[strategy]?.get() ?: 0) > 3) {
                    netMemory[category] = strategy
                }
            }

            if (latencyMs > 0) {
                val currentAvg = strategyLatency.getOrPut(strategy) { java.util.concurrent.atomic.AtomicLong(0) }
                if (currentAvg.get() == 0L) {
                    currentAvg.set(latencyMs)
                } else {
                    currentAvg.set((currentAvg.get() * 7 + latencyMs) / 8) // Smooth moving average
                }
            }
            
            consecutiveFailures.remove(strategy)
            circuitBreakers.remove(strategy)
        } else {
            failureHistory.getOrPut(strategy) { AtomicInteger(0) }.incrementAndGet()
            
            if (host != null) {
                val hostFails = consecutiveFailuresByHost.getOrPut(host) { AtomicInteger(0) }.incrementAndGet()
                if (hostFails > 4) {
                    Log.w("DpiEngine", "Host $host has $hostFails consecutive failures. Escalating strategy.")
                }
            }

            val penalty = when (reason) {
                FailureReason.TCP_RESET -> 100 // High confidence DPI block
                FailureReason.CENSORSHIP_STALL -> 120
                FailureReason.DNS_POISONED -> 50
                FailureReason.SSL_HANDSHAKE_ERROR -> 60
                FailureReason.MTU_EXCEEDED -> 40
                FailureReason.TIMEOUT -> 30
                else -> 35
            }
            
            strategyScores[category]?.get(strategy)?.let { score ->
                score.addAndGet(-penalty)
                if (score.get() < 5) score.set(5)
            }
            
            val fails = consecutiveFailures.getOrPut(strategy) { AtomicInteger(0) }.incrementAndGet()
            if (fails >= 5) {
                // Trigger circuit breaker for 5 minutes
                circuitBreakers[strategy] = System.currentTimeMillis() + 300_000
                Log.w("DpiEngine", "Circuit breaker triggered for $strategy due to $fails consecutive failures")
            }

            if (host != null && (reason == FailureReason.TCP_RESET || reason == FailureReason.CENSORSHIP_STALL)) {
                val hostBlacklist = hostStrategyBlacklist.getOrPut(host) { ConcurrentHashMap() }
                // Progressive backoff for blacklisted host-strategy pairs
                val currentLevel = hostBlacklist[strategy] ?: 0L
                val waitTime = if (System.currentTimeMillis() > currentLevel) 900_000L else 3_600_000L // 15m then 60m
                hostBlacklist[strategy] = System.currentTimeMillis() + waitTime
                Log.d("DpiEngine", "Host $host blacklisted for strategy $strategy for ${waitTime/60000} min")
            }
        }
    }

    private val consecutiveFailuresByHost = ConcurrentHashMap<String, AtomicInteger>()

    fun getBestStrategy(category: HostCategory, host: String? = null): BypassStrategy {
        val now = System.currentTimeMillis()
        val netType = BypassConfig.currentNetworkType.value.toString()
        
        // Host-based escalation: If too many failures, use chain
        if (host != null) {
            val hostFails = consecutiveFailuresByHost[host]?.get() ?: 0
            if (hostFails > 4) {
                val lastMem = hostSpecificMemory[host]
                if (lastMem != null) {
                    val escalated = getFallbackStrategy(lastMem.strategy)
                    if (escalated != null && (circuitBreakers[escalated] ?: 0L) < now) {
                        return escalated
                    }
                }
                // If no specific memory or chain failed, use EXTREME version of category preference
                return getBestExtremeStrategy(host)
            }
        }

        // 1. Active Probing for high-priority host failure recovery
        if (host != null && ProxyStats.censorshipIntensity.value > 80) {
            val blacklist = hostStrategyBlacklist[host]
            if (blacklist != null && blacklist.size > 3) {
                 // Too many failures for this host, trigger immediate exploration of EXTREME strategies
                 scope.launch { triggerMicroProbe(host, category) }
            }
        }

        // 0. High Intensity override: use hybrid or nuclear strategies if censorship is extreme
        if (ProxyStats.censorshipIntensity.value > 95) {
            val nuclear = listOf(BypassStrategy.TCP_COMBINED_NUCLEAR, BypassStrategy.UDP_COMBINED_NUCLEAR)
            val bestNuclear = nuclear.maxByOrNull { getAverageScore(it) } ?: BypassStrategy.TCP_COMBINED_NUCLEAR
            if ((circuitBreakers[bestNuclear] ?: 0L) < now) return bestNuclear
        } else if (ProxyStats.censorshipIntensity.value > 85) {
            val hybrids = listOf(BypassStrategy.TCP_COMBINED_HYBRID, BypassStrategy.UDP_COMBINED_HYBRID)
            val bestHybrid = hybrids.maxByOrNull { getAverageScore(it) } ?: BypassStrategy.TCP_COMBINED_HYBRID
            if ((circuitBreakers[bestHybrid] ?: 0L) < now) return bestHybrid
        }

        // 1. Check Network Memory for a known-good strategy for this category on this network
        networkStrategyMemory[netType]?.get(category)?.let { strat ->
            if ((circuitBreakers[strat] ?: 0L) < now) {
                val hostBlacklist = host?.let { hostStrategyBlacklist[it] }
                if (hostBlacklist?.get(strat) == null || hostBlacklist[strat]!! < now) {
                    return strat
                }
            }
        }

        val catScores = strategyScores[category] ?: return BypassStrategy.SNI_SPLIT
        
        // Filter out strategies under circuit breaker or host-specific blacklist
        val hostBlacklist = host?.let { hostStrategyBlacklist[it] }
        val validStrategies = catScores.entries.filter { (strat, _) ->
            (circuitBreakers[strat] ?: 0L) < now && (hostBlacklist?.get(strat) ?: 0L) < now
        }
        
        if (validStrategies.isEmpty()) {
            if (host != null) hostStrategyBlacklist.remove(host)
            circuitBreakers.clear() // Emergency clear
            return BypassStrategy.CHAOS
        }

        val rnd = java.util.concurrent.ThreadLocalRandom.current()
        
        // Exploration: 7% chance to try a random strategy to keep data fresh
        if (rnd.nextInt(100) < 7) {
            return validStrategies.random().key
        }
        
        // Context-aware boost based on current DpiType detected globally
        val currentDpi = ProxyStats.currentDpiType.value
        
        // Softmax-like selection: Pick strategy with probability proportional to its score
        val totalScore = validStrategies.sumOf { (strat, score) ->
            var s = score.get().toDouble()
            
            // Maturity Bonus
            s += (strategyMaturity[strat]?.get() ?: 0) / 6.0
            
            // Contextual Boosts
            when (currentDpi) {
                DpiType.TLS_SNI_BLOCK -> {
                    if (strat.family == StrategyFamily.TLS || strat.family == StrategyFamily.FRAGMENTATION) s *= 1.8
                }
                DpiType.TCP_RESET -> {
                    if (strat.family == StrategyFamily.TCP || strat.family == StrategyFamily.FRAGMENTATION) s *= 1.8
                }
                DpiType.UDP_BLOCK -> if (strat.family == StrategyFamily.UDP || strat.family == StrategyFamily.QUIC) s *= 1.8
                DpiType.BLACKHOLE -> if (strat.group == StrategyGroup.EXTREME || strat.group == StrategyGroup.HEAVY) s *= 2.5
                else -> {}
            }
            
            // Host Category Specific Prios
            when (category) {
                HostCategory.STREAMING, HostCategory.SOCIAL -> if (strat.group == StrategyGroup.EXTREME || strat.group == StrategyGroup.HEAVY) s *= 1.4
                HostCategory.AI, HostCategory.FINANCE -> if (strat.family == StrategyFamily.FRAGMENTATION) s *= 1.3
                else -> {}
            }
            
            val latency = strategyLatency[strat]?.get() ?: 200L
            val latencyPenalty = (latency / 15.0).coerceAtMost(60.0)
            (s - latencyPenalty).coerceAtLeast(5.0)
        }

        var randomPivot = rnd.nextDouble() * totalScore
        for ((strat, score) in validStrategies) {
            var s = score.get().toDouble()
            s += (strategyMaturity[strat]?.get() ?: 0) / 8.0
            when (currentDpi) {
                DpiType.TLS_SNI_BLOCK -> if (strat.family == StrategyFamily.TLS || strat.family == StrategyFamily.FRAGMENTATION) s *= 1.5
                DpiType.TCP_RESET -> if (strat.family == StrategyFamily.TCP || strat.family == StrategyFamily.FRAGMENTATION) s *= 1.5
                DpiType.UDP_BLOCK -> if (strat.family == StrategyFamily.UDP || strat.family == StrategyFamily.QUIC) s *= 1.5
                DpiType.BLACKHOLE -> if (strat.group == StrategyGroup.EXTREME || strat.group == StrategyGroup.HEAVY) s *= 2.0
                else -> {}
            }
            val latency = strategyLatency[strat]?.get() ?: 200L
            val latencyPenalty = (latency / 20.0).coerceAtMost(50.0)
            val weight = (s - latencyPenalty).coerceAtLeast(10.0)
            
            randomPivot -= weight
            if (randomPivot <= 0) return strat
        }

        return validStrategies.maxByOrNull { it.value.get() }?.key ?: BypassStrategy.SNI_SPLIT
    }

    fun boostStrategyFamily(family: StrategyFamily, host: String?) {
        val category = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
        strategyScores[category]?.forEach { (strat, score) ->
            if (strat.family == family) {
                val boost = when (strat.group) {
                    StrategyGroup.EXTREME -> 60
                    StrategyGroup.HEAVY -> 40
                    StrategyGroup.MEDIUM -> 25
                    else -> 15
                }
                score.addAndGet(boost)
                if (score.get() > 3000) score.set(3000)
            }
        }
    }

    fun clearCircuitBreakers() {
        circuitBreakers.clear()
    }

    fun getAverageScore(strategy: BypassStrategy): Double {
        return strategyScores.values.map { it[strategy]?.get() ?: 0 }.map { it.toDouble() }.average()
    }

    fun resetStrategyScoresForNetworkChange() {
        Log.i("DpiEngine", "Network change detected, performing partial score reset for faster adaptation.")
        
        // Trigger quick scan to assess new network immediately
        PinkVpnService.instance?.let { performQuickScan(it) }

        strategyScores.values.forEach { catScores ->
            catScores.values.forEach { score ->
                val s = score.get()
                // Bring scores closer to baseline (100) but keep some "memory" of what was good
                if (s > 300) score.set((s * 0.4 + 60).toInt())
                else if (s < 50) score.set(80)
                else score.set(100)
            }
        }
        circuitBreakers.clear()
        consecutiveFailures.clear()
        successHistory.clear()
        failureHistory.clear()
    }

    private fun analyzeAndAdjust() {
        // Apply score decay to allow for adaptation to new censorship patterns
        decayScores()
        
        // Cleanup memory
        if (hostStrategyBlacklist.size > 500) {
            val now = System.currentTimeMillis()
            val toRemove = hostStrategyBlacklist.filterValues { map -> map.values.all { it < now } }.keys
            toRemove.forEach { hostStrategyBlacklist.remove(it) }
            if (hostStrategyBlacklist.size > 1000) hostStrategyBlacklist.clear() // Hard reset
        }

        val totalSuccess = successHistory.values.sumOf { it.get() }
        val totalFailure = failureHistory.values.sumOf { it.get() }
        
        if (hostSpecificMemory.size > 1000) {
            val now = System.currentTimeMillis()
            val expiry = 86400000L * 7 // 7 days
            hostSpecificMemory.entries.removeIf { now - it.value.timestamp > expiry }
        }

        if (totalSuccess + totalFailure == 0) {
            // Passive recovery when no data: slowly reduce intensity
            ProxyStats.updateCensorshipIntensity((ProxyStats.censorshipIntensity.value - 2).coerceAtLeast(0))
            return
        }

        val globalSuccessRate = (totalSuccess.toDouble() / (totalSuccess + totalFailure) * 100).toInt()
        
        // --- PANIC MODE LOGIC ---
        val calculatedIntensity = (
            getCensorshipFingerprint().rstRate * 55 + 
            getCensorshipFingerprint().sniBlockRate * 65 + 
            getCensorshipFingerprint().timeoutRate * 20 + 
            getCensorshipFingerprint().stallRate * 35
        ).toInt()

        if (globalSuccessRate < 15 && calculatedIntensity > 40) {
            if (System.currentTimeMillis() - lastPanicTime > 300000) { // Throttle panic mode triggers
                lastPanicTime = System.currentTimeMillis()
                Log.e("DpiEngine", "CRITICAL: Global success rate is $globalSuccessRate%. TRIGGERING PANIC PROTOCOL.")
                ProxyStats.logRecovery("CRITICAL: Network collapse detected. Triggering Panic Protocol.")
                
                // Nuclear reset of stale strategy data
                hostSpecificMemory.clear()
                hostStrategyBlacklist.clear()
                circuitBreakers.clear()
                
                // Temporarily boost heavy strategies globally
                strategyScores.forEach { (_, scores) ->
                    scores.forEach { (strat, score) ->
                        if (strat.group == StrategyGroup.EXTREME || strat.group == StrategyGroup.HEAVY) {
                            score.addAndGet(100)
                        } else {
                            score.set(50) // Reset others to low
                        }
                    }
                }
                
                PinkVpnService.instance?.let { performQuickScan(it) }
            }
        }
        // -----------------------

        // Calculate Network Stability Score: combination of success rate and reset frequency
        val fingerprint = getCensorshipFingerprint()
        
        // Automatic Censorship Intensity Calculation: Non-linear weighting
        // Resets and SNI blocks are much more indicative of DPI presence than simple timeouts
        val intensityValue = (
            fingerprint.rstRate * 55 + 
            fingerprint.sniBlockRate * 65 + 
            fingerprint.timeoutRate * 20 + 
            fingerprint.stallRate * 35 +
            (fingerprint.jitter / 150).coerceAtMost(15.0)
        ).toInt().coerceIn(0, 100)
        
        // Exponential smoothing for intensity updates to avoid jitter
        val currentIntensity = ProxyStats.censorshipIntensity.value
        val targetIntensity = if (intensityValue > currentIntensity) {
            // React faster to blocking
            (currentIntensity * 0.3 + intensityValue * 0.7).toInt()
        } else {
            // Recover faster if everything is perfect for a while
            if (globalSuccessRate > 95 && fingerprint.rstRate < 0.05) {
                (currentIntensity * 0.7 + intensityValue * 0.3).toInt()
            } else {
                (currentIntensity * 0.9 + intensityValue * 0.1).toInt()
            }
        }
        
        if (Math.abs(targetIntensity - currentIntensity) >= 1) {
            ProxyStats.updateCensorshipIntensity(targetIntensity)
            Log.i("DpiEngine", "Automatic Intensity updated: $targetIntensity (Success Rate: $globalSuccessRate%)")
        }

        val stability = (globalSuccessRate * 0.5 + (100 - (fingerprint.rstRate + fingerprint.sniBlockRate) * 100).coerceAtLeast(0.0) * 0.5).toInt().coerceIn(0, 100)
        ProxyStats.updateStabilityScore(stability)
        
        // Adaptive MTU Adjustment
        if (fingerprint.timeoutRate > 0.4 || fingerprint.stallRate > 0.5 || fingerprint.jitter > 1000) {
             val mtu = BypassConfig.currentMtu.value
             if (mtu > 1000) {
                 BypassConfig.setMtu(mtu - 32)
                 ProxyStats.logRecovery("Autonomous Engine: Critical packet drop detected. Down-scaling MTU.")
             }
        } else if (stability > 90 && globalSuccessRate > 90 && BypassConfig.currentMtu.value < 1400) {
             BypassConfig.setMtu(BypassConfig.currentMtu.value + 16)
        }
        
        // Jitter-based family boosting
        if (fingerprint.jitter > 800) {
            boostStrategyFamily(StrategyFamily.ADAPTIVE, null)
            ProxyStats.logRecovery("High Network Jitter (${fingerprint.jitter.toInt()}ms). Activating Adaptive Family.")
        }

        // Auto-Panic Mode trigger: More aggressive when seeing TCP Reset spikes
        val isPanic = BypassConfig.isPanicModeFlow.value
        if (!isPanic && (globalSuccessRate < 35 || fingerprint.rstRate > 0.35 || fingerprint.sniBlockRate > 0.5)) {
             BypassConfig.setPanicMode(true)
             Log.e("DpiEngine", "EMERGENCY PANIC TRIGGERED: High Block Rate Detected.")
        } else if (isPanic && globalSuccessRate > 75 && fingerprint.rstRate < 0.1) {
             BypassConfig.setPanicMode(false)
             Log.i("DpiEngine", "Panic mode deactivated: Success rate recovered.")
        }

        // Strategy Aging: trend back to baseline with intensity-aware decay
        strategyScores.values.forEach { catScores ->
            catScores.values.forEach { score ->
                val s = score.get()
                val intensityFactor = ProxyStats.censorshipIntensity.value / 100.0
                
                if (s > 100) {
                    // Decay good strategies slower if intensity is high (keep what works)
                    val decay = if (intensityFactor > 0.8) 0.99 else 0.95
                    score.set((s * decay + 100 * (1.0 - decay)).toInt())
                } else if (s < 100) {
                    // Recover failed strategies slower if intensity is high (avoid re-trying broken stuff too often)
                    val recovery = if (intensityFactor > 0.8) 1.01 else 1.05
                    score.set((s * recovery + 2).toInt().coerceAtMost(100))
                }
            }
        }
        
        // Global Bypass Optimization
        BypassConfig.frag1 = getRecommendedFragSize()
        BypassConfig.delay1 = getRecommendedDelay()
        
        pruneStrategies()
        saveScores(ProxyDispatcher.context!!)

        if (totalSuccess + totalFailure > 1000) {
            successHistory.clear()
            failureHistory.clear()
        }
    }

    private suspend fun triggerMicroProbe(host: String, category: HostCategory) {
        val probes = BypassStrategy.entries.filter { it.group == StrategyGroup.EXTREME || it.group == StrategyGroup.HEAVY }
            .shuffled().take(3)
            
        val resolved = try { RobustResolver.resolve(host) } catch (e: Throwable) { emptyList() }
        if (resolved.isEmpty()) return
        val addr = resolved.first()

        for (strat in probes) {
            try {
                val start = System.currentTimeMillis()
                val ok = withTimeoutOrNull(3000) {
                    val s = java.net.Socket()
                    try {
                        s.connect(java.net.InetSocketAddress(addr, 443), 1500)
                        val out = s.getOutputStream()
                        val fake = FakePacketHelper.buildRealisticTlsHello(host)
                        val config = BypassConfig.getSessionConfig(host, strat, 50)
                        BypassConfig.applyBypass(s, out, fake, fake.size, config, host)
                        s.soTimeout = 1500
                        val i = s.getInputStream().read()
                        i != -1
                    } catch (e: Throwable) {
                        false
                    } finally {
                        try { s.close() } catch (e: Throwable) {}
                    }
                }
                val latency = System.currentTimeMillis() - start
                if (ok == true) {
                    recordResult(strat, true, category, latencyMs = latency, host = host)
                    Log.i("DpiEngine", "Micro-probe SUCCESS for $host using ${strat.name}")
                    return
                }
            } catch (e: Throwable) {}
            delay(200)
        }
    }

    private fun pruneStrategies() {
        strategyScores.forEach { (_, scores) ->
            scores.forEach { (strat, score) ->
                if (score.get() < 30) {
                    circuitBreakers[strat] = System.currentTimeMillis() + 300000 
                }
            }
        }
    }

    fun getCensorshipReport(): String {
        val sb = StringBuilder()
        sb.append("Intensity: ${ProxyStats.censorshipIntensity.value}%\n")
        sb.append("Performers:\n")
        strategyScores.forEach { (cat, scores) ->
            val best = scores.maxByOrNull { it.value.get() }
            if (best != null && best.value.get() > 100) {
                sb.append("$cat: ${best.key}(${best.value})\n")
            }
        }
        return sb.toString()
    }

    private fun decayScores() {
        // Slowly move all scores towards a baseline (e.g., 500)
        // This ensures that strategies that worked long ago but no longer work
        // eventually lose their high score, and new strategies get a chance.
        strategyScores.values.forEach { catScores ->
            catScores.values.forEach { score ->
                val s = score.get()
                if (s > 500) {
                    score.addAndGet(-(s - 500) / 100 - 1)
                } else if (s < 500) {
                    score.addAndGet((500 - s) / 50 + 1)
                }
            }
        }
    }

    private fun saveHostMemory(context: android.content.Context) {
        val prefs = context.getSharedPreferences("dpi_engine_host_memory", android.content.Context.MODE_PRIVATE)
        val editor = prefs.edit()
        val now = System.currentTimeMillis()
        val expiry = 86400000L * 7
        hostSpecificMemory.forEach { (host, mem) ->
            if (now - mem.timestamp < expiry) {
                editor.putString(host, "${mem.strategy.name}|${mem.timestamp}")
            }
        }
        editor.apply()
    }

    private fun loadHostMemory(context: android.content.Context) {
        val prefs = context.getSharedPreferences("dpi_engine_host_memory", android.content.Context.MODE_PRIVATE)
        val now = System.currentTimeMillis()
        val expiry = 86400000L * 7
        prefs.all.forEach { (host, value) ->
            if (value is String) {
                val parts = value.split("|")
                if (parts.size == 2) {
                    try {
                        val strat = BypassStrategy.valueOf(parts[0])
                        val ts = parts[1].toLong()
                        if (now - ts < expiry) {
                            hostSpecificMemory[host] = HostMemory(strat, ts)
                        }
                    } catch (e: Throwable) {}
                }
            }
        }
    }

    private fun saveScores(context: android.content.Context) {
        saveHostMemory(context)
        val prefs = context.getSharedPreferences("dpi_engine_scores", android.content.Context.MODE_PRIVATE)
        val editor = prefs.edit()
        strategyScores.forEach { (cat, scores) ->
            scores.forEach { (strat, score) ->
                editor.putInt("${cat.name}_${strat.name}", score.get())
            }
        }
        networkStrategyMemory.forEach { (netType, catMap) ->
            catMap.forEach { (cat, strat) ->
                editor.putString("netmem_${netType}_${cat.name}", strat.name)
            }
        }
        editor.apply()
    }

    private fun loadScores(context: android.content.Context) {
        loadHostMemory(context)
        val prefs = context.getSharedPreferences("dpi_engine_scores", android.content.Context.MODE_PRIVATE)
        strategyScores.forEach { (cat, scores) ->
            scores.forEach { (strat, score) ->
                val saved = prefs.getInt("${cat.name}_${strat.name}", -1)
                if (saved != -1) score.set(saved)
            }
        }
        prefs.all.keys.filter { it.startsWith("netmem_") }.forEach { key ->
            val parts = key.removePrefix("netmem_").split("_", limit = 2)
            if (parts.size == 2) {
                val netType = parts[0]
                val catName = parts[1]
                val stratName = prefs.getString(key, null)
                if (stratName != null) {
                    try {
                        val cat = HostCategory.valueOf(catName)
                        val strat = BypassStrategy.valueOf(stratName)
                        val catMap = networkStrategyMemory.getOrPut(netType) { ConcurrentHashMap() }
                        catMap[cat] = strat
                    } catch (e: Throwable) {}
                }
            }
        }
    }

    fun getRecommendedFragSize(): Int {
        val intensity = ProxyStats.censorshipIntensity.value
        val fingerprint = getCensorshipFingerprint()
        
        return when {
            intensity > 95 || fingerprint.rstRate > 0.4 -> 1
            intensity > 85 || fingerprint.sniBlockRate > 0.5 -> 2
            intensity > 70 -> 3
            intensity > 50 -> 6
            else -> 12
        }
    }

    fun getRecommendedDelay(): Long {
        val intensity = ProxyStats.censorshipIntensity.value
        val fingerprint = getCensorshipFingerprint()
        
        return when {
            intensity > 95 || fingerprint.stallRate > 0.3 -> 200L
            intensity > 85 -> 100L
            intensity > 70 -> 40L
            intensity > 40 -> 15L
            else -> 4L
        }
    }
}
