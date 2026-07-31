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

    private var lastGlobalReset = System.currentTimeMillis()
    private val eventHistory = ConcurrentHashMap<DpiType, AtomicInteger>()

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

    fun recordResult(strategy: BypassStrategy, success: Boolean, category: HostCategory = HostCategory.OTHER, reason: FailureReason? = null, latencyMs: Long = 0) {
        if (success) {
            successHistory.getOrPut(strategy) { AtomicInteger(0) }.incrementAndGet()
            strategyScores[category]?.get(strategy)?.let { score ->
                score.addAndGet(10)
                if (score.get() > 2000) score.set(2000)
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
                FailureReason.TCP_RESET -> 40
                FailureReason.SSL_HANDSHAKE_ERROR -> 30
                FailureReason.TIMEOUT -> 15
                else -> 20
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
        }
    }

    fun getBestStrategy(category: HostCategory): BypassStrategy {
        val catScores = strategyScores[category] ?: return BypassStrategy.SNI_SPLIT
        val now = System.currentTimeMillis()
        
        // Filter out strategies under circuit breaker
        val validStrategies = catScores.entries.filter { (strat, _) ->
            (circuitBreakers[strat] ?: 0L) < now
        }
        
        if (validStrategies.isEmpty()) {
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
        
        // Find strategy with best combined score (score - latency_penalty + context_boost)
        return validStrategies
            .shuffled()
            .maxByOrNull { (strat, score) ->
                var s = score.get().toDouble()
                
                // Contextual Boosts
                when (currentDpi) {
                    DpiType.TLS_SNI_BLOCK -> if (strat.family == StrategyFamily.TLS || strat.family == StrategyFamily.FRAGMENTATION) s += 100
                    DpiType.TCP_RESET -> if (strat.family == StrategyFamily.TCP || strat.family == StrategyFamily.FRAGMENTATION) s += 100
                    DpiType.UDP_BLOCK -> if (strat.family == StrategyFamily.UDP || strat.family == StrategyFamily.QUIC) s += 100
                    DpiType.BLACKHOLE -> if (strat.group == StrategyGroup.EXTREME || strat.group == StrategyGroup.HEAVY) s += 150
                    else -> {}
                }
                
                val latency = strategyLatency[strat]?.get() ?: 200L
                val latencyPenalty = (latency / 15).coerceAtMost(40).toDouble()
                s - latencyPenalty + rnd.nextInt(-10, 10)
            }
            ?.key ?: BypassStrategy.SNI_SPLIT
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
        
        // Strategy Aging: trend back to baseline to allow re-evaluation of previously failed strategies
        strategyScores.values.forEach { catScores ->
            catScores.values.forEach { score ->
                val s = score.get()
                if (s > 100) {
                    val decay = if (ProxyStats.censorshipIntensity.value > 80) 0.95 else 0.85
                    score.set((s * decay + 100 * (1.0 - decay)).toInt())
                } else if (s < 100) {
                    score.set((s * 1.05 + 5).toInt().coerceAtMost(100))
                }
                
                if (s < 5) score.set(50) // Don't let it stay at zero forever
            }
        }
        
        pruneStrategies()
        saveScores(ProxyDispatcher.context!!)

        // Reset history periodically to stay adaptive to network changes
        if (totalSuccess + totalFailure > 300) {
            successHistory.clear()
            failureHistory.clear()
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
    }

    fun getRecommendedFragSize(): Int {
        val intensity = ProxyStats.censorshipIntensity.value
        return when {
            intensity > 90 -> 1
            intensity > 75 -> 2
            intensity > 50 -> 4
            else -> 10
        }
    }

    fun getRecommendedDelay(): Long {
        val intensity = ProxyStats.censorshipIntensity.value
        return when {
            intensity > 90 -> 150L
            intensity > 70 -> 50L
            intensity > 40 -> 20L
            else -> 5L
        }
    }
}
