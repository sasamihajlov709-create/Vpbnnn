package com.aistudio.pinkproxy.fresh

import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

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

    private var lastGlobalReset = System.currentTimeMillis()
    private val eventHistory = ConcurrentHashMap<DpiType, AtomicInteger>()
    
    data class CensorshipFingerprint(
        val rstRate: Double,
        val sniBlockRate: Double,
        val udpBlockRate: Double,
        val timeoutRate: Double,
        val stallRate: Double,
        val intensity: Int
    )

    fun getCensorshipFingerprint(): CensorshipFingerprint {
        val total = eventHistory.values.sumOf { it.get() }.toDouble().coerceAtLeast(1.0)
        return CensorshipFingerprint(
            rstRate = (eventHistory[DpiType.TCP_RESET]?.get() ?: 0) / total,
            sniBlockRate = (eventHistory[DpiType.TLS_SNI_BLOCK]?.get() ?: 0) / total,
            udpBlockRate = (eventHistory[DpiType.UDP_BLOCK]?.get() ?: 0) / total,
            timeoutRate = (eventHistory[DpiType.CONNECTION_TIMEOUT]?.get() ?: 0) / total,
            stallRate = ((eventHistory[DpiType.TCP_STALL]?.get() ?: 0) + (eventHistory[DpiType.SSL_STALL]?.get() ?: 0)) / total,
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

    fun performInitialScan(context: android.content.Context) {
        scope.launch {
            Log.i("DpiEngine", "Starting automated censorship fingerprinting...")
            val targets = listOf("google.com", "youtube.com", "telegram.org")
            val probes = listOf(
                BypassStrategy.TCP_RETRANS_FAKE,
                BypassStrategy.TLS_SNI_FRAGMENT,
                BypassStrategy.SNI_SPLIT
            )
            
            targets.forEach { host ->
                probes.forEach { strat ->
                    try {
                        val ok = withTimeoutOrNull(5000) {
                            RobustResolver.resolve(host)
                        }
                        if (ok != null && ok.isNotEmpty()) {
                            recordResult(strat, true, HostClassifier.classify(host), latencyMs = 100)
                        } else {
                            recordResult(strat, false, HostClassifier.classify(host), reason = FailureReason.TIMEOUT)
                        }
                    } catch (e: Throwable) {}
                    delay(500)
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
            if (rate < 15 && System.currentTimeMillis() - lastGlobalReset > 600_000) {
                Log.e("DpiEngine", "GLOBAL STALL DETECTED (Success rate $rate%). Resetting all scores.")
                resetEverything()
                lastGlobalReset = System.currentTimeMillis()
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
        val extreme = BypassStrategy.entries.filter { it.group == StrategyGroup.EXTREME }
        return extreme.maxByOrNull { getAverageScore(it) } ?: BypassStrategy.ZAPRET_EXTREME
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

    fun recordResult(strategy: BypassStrategy, success: Boolean, category: HostCategory = HostCategory.OTHER, reason: FailureReason? = null, latencyMs: Long = 0, host: String? = null) {
        if (success) {
            successHistory.getOrPut(strategy) { AtomicInteger(0) }.incrementAndGet()
            strategyMaturity.getOrPut(strategy) { AtomicInteger(0) }.incrementAndGet()
            
            strategyScores[category]?.get(strategy)?.let { score ->
                // Fast recovery for successful strategies
                val bonus = if (latencyMs in 1..300) 25 else 10
                score.addAndGet(bonus)
                if (score.get() > 3000) score.set(3000)
            }
            
            if (host != null) {
                hostStrategyBlacklist[host]?.remove(strategy)
                
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
            
            val penalty = when (reason) {
                FailureReason.TCP_RESET -> 80 // High confidence DPI block
                FailureReason.CENSORSHIP_STALL -> 100
                FailureReason.DNS_POISONED -> 40
                FailureReason.SSL_HANDSHAKE_ERROR -> 50
                FailureReason.MTU_EXCEEDED -> 30
                FailureReason.TIMEOUT -> 20
                else -> 25
            }
            
            strategyScores[category]?.get(strategy)?.let { score ->
                score.addAndGet(-penalty)
                if (score.get() < 10) score.set(10)
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
                val waitTime = if (System.currentTimeMillis() > currentLevel) 600_000L else 1_800_000L // 10m then 30m
                hostBlacklist[strategy] = System.currentTimeMillis() + waitTime
                Log.d("DpiEngine", "Host $host blacklisted for strategy $strategy for ${waitTime/60000} min")
            }
        }
    }

    fun getBestStrategy(category: HostCategory, host: String? = null): BypassStrategy {
        val now = System.currentTimeMillis()
        val netType = BypassConfig.currentNetworkType.value.toString()
        
        // 0. Active Probing for high-priority host failure recovery
        if (host != null && ProxyStats.censorshipIntensity.value > 80) {
            val blacklist = hostStrategyBlacklist[host]
            if (blacklist != null && blacklist.size > 3) {
                 // Too many failures for this host, trigger immediate exploration of EXTREME strategies
                 scope.launch { triggerMicroProbe(host, category) }
            }
        }

        // 0. High Intensity override: use hybrid strategies if censorship is extreme
        if (ProxyStats.censorshipIntensity.value > 90) {
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
            s += (strategyMaturity[strat]?.get() ?: 0) / 8.0
            
            // Contextual Boosts
            when (currentDpi) {
                DpiType.TLS_SNI_BLOCK -> {
                    if (strat.family == StrategyFamily.TLS || strat.family == StrategyFamily.FRAGMENTATION) s *= 1.5
                }
                DpiType.TCP_RESET -> {
                    if (strat.family == StrategyFamily.TCP || strat.family == StrategyFamily.FRAGMENTATION) s *= 1.5
                }
                DpiType.UDP_BLOCK -> if (strat.family == StrategyFamily.UDP || strat.family == StrategyFamily.QUIC) s *= 1.5
                DpiType.BLACKHOLE -> if (strat.group == StrategyGroup.EXTREME || strat.group == StrategyGroup.HEAVY) s *= 2.0
                else -> {}
            }
            
            val latency = strategyLatency[strat]?.get() ?: 200L
            val latencyPenalty = (latency / 20.0).coerceAtMost(50.0)
            (s - latencyPenalty).coerceAtLeast(10.0)
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
        val totalSuccess = successHistory.values.sumOf { it.get() }
        val totalFailure = failureHistory.values.sumOf { it.get() }
        
        if (totalSuccess + totalFailure == 0) return

        val globalSuccessRate = (totalSuccess.toDouble() / (totalSuccess + totalFailure) * 100).toInt()
        ProxyStats.updateCensorshipIntensity(100 - globalSuccessRate)
        
        // Calculate Network Stability Score: combination of success rate and reset frequency
        val fingerprint = getCensorshipFingerprint()
        val stability = (globalSuccessRate * 0.6 + (100 - fingerprint.rstRate * 100) * 0.4).toInt().coerceIn(0, 100)
        ProxyStats.updateStabilityScore(stability)
        
        // Auto-Panic Mode trigger: More aggressive when seeing TCP Reset spikes
        if ((globalSuccessRate < 25 && totalSuccess + totalFailure > 10) || fingerprint.rstRate > 0.4) {
             if (!BypassConfig.isPanicModeFlow.value) {
                 BypassConfig.setPanicMode(true)
                 Log.e("DpiEngine", "AUTO-PANIC TRIGGERED: High Reset Rate (${(fingerprint.rstRate*100).toInt()}%) or Low Success ($globalSuccessRate%)")
             }
        } else if (globalSuccessRate > 65 && BypassConfig.isPanicModeFlow.value) {
             BypassConfig.setPanicMode(false)
             Log.i("DpiEngine", "Panic mode deactivated: Success rate recovered to $globalSuccessRate%")
        }

        // Strategy Aging: trend back to baseline to allow re-evaluation
        strategyScores.values.forEach { catScores ->
            catScores.values.forEach { score ->
                val s = score.get()
                if (s > 100) {
                    val decay = if (ProxyStats.censorshipIntensity.value > 85) 0.98 else 0.90
                    score.set((s * decay + 100 * (1.0 - decay)).toInt())
                } else if (s < 100) {
                    val recovery = if (ProxyStats.censorshipIntensity.value < 20) 1.2 else 1.08
                    score.set((s * recovery + 5).toInt().coerceAtMost(100))
                }
                if (s < 10) score.set(40) 
            }
        }
        
        // Adjust fragmentation and delays globally based on intensity
        BypassConfig.frag1 = getRecommendedFragSize()
        BypassConfig.delay1 = getRecommendedDelay()
        
        // Clean up stale blacklist entries to prevent memory leaks
        val now = System.currentTimeMillis()
        hostStrategyBlacklist.keys().toList().forEach { host ->
            val hostMap = hostStrategyBlacklist[host]
            if (hostMap != null) {
                hostMap.entries.removeIf { it.value < now }
                if (hostMap.isEmpty()) {
                    hostStrategyBlacklist.remove(host)
                }
            }
        }

        pruneStrategies()
        saveScores(ProxyDispatcher.context!!)

        if (totalSuccess + totalFailure > 500) {
            successHistory.clear()
            failureHistory.clear()
        }
    }

    private suspend fun triggerMicroProbe(host: String, category: HostCategory) {
        val probes = BypassStrategy.entries.filter { it.group == StrategyGroup.EXTREME || it.group == StrategyGroup.HEAVY }
            .shuffled().take(3)
            
        for (strat in probes) {
            try {
                val ok = withTimeoutOrNull(3000) {
                    RobustResolver.resolve(host)
                }
                if (ok != null && ok.isNotEmpty()) {
                    recordResult(strat, true, category, latencyMs = 200, host = host)
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

    private fun saveScores(context: android.content.Context) {
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
