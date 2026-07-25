package com.aistudio.pinkproxy.fresh

import android.content.Context
import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.net.*
import java.nio.ByteBuffer
import java.util.*
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.io.*
object BypassConfig {
    private val _strategy = MutableStateFlow(BypassStrategy.SNI_SPLIT)
    val strategy: StateFlow<BypassStrategy> = _strategy.asStateFlow()
    
    private val _censorshipLevel = MutableStateFlow(0) // 0-100
    val censorshipLevel: StateFlow<Int> = _censorshipLevel.asStateFlow()

    private val strategyGrouping = BypassStrategy.entries.groupBy {
        val totalWeight = it.cost + it.risk
        when {
            totalWeight <= 4 -> StrategyGroup.LIGHT
            totalWeight <= 6 -> StrategyGroup.MEDIUM
            totalWeight <= 8 -> StrategyGroup.HEAVY
            else -> StrategyGroup.EXTREME
        }
    }

    private val _currentNetworkType = MutableStateFlow(NetworkType.UNKNOWN)
    val currentNetworkType: StateFlow<NetworkType> = _currentNetworkType.asStateFlow()

    private val strategyScores = ConcurrentHashMap<HostCategory, ConcurrentHashMap<BypassStrategy, AtomicInteger>>()
    private val hostBlacklist = ConcurrentHashMap<String, ConcurrentHashMap<BypassStrategy, Long>>()
    class StratStats(val successes: AtomicLong = AtomicLong(), val failures: AtomicLong = AtomicLong(), val totalRtt: AtomicLong = AtomicLong())
    private val strategyStats = ConcurrentHashMap<BypassStrategy, StratStats>()

    private val _currentRttMs = MutableStateFlow(50L)
    val currentRttMs: StateFlow<Long> = _currentRttMs.asStateFlow()

    private val _currentFragSizeState = MutableStateFlow(1)
    val currentFragSizeState: StateFlow<Int> = _currentFragSizeState.asStateFlow()

    private val _isChargingFlow = MutableStateFlow(true)
    val isChargingFlow: StateFlow<Boolean> = _isChargingFlow.asStateFlow()

    private val _isPanicModeFlow = MutableStateFlow(false)
    val isPanicModeFlow: StateFlow<Boolean> = _isPanicModeFlow.asStateFlow()

    private val _currentMtu = MutableStateFlow(1400)
    val currentMtu: StateFlow<Int> = _currentMtu.asStateFlow()

    @Volatile var isAutoTuning = true
    @Volatile var frag1 = 1
    @Volatile var frag2 = 5
    @Volatile var frag3 = 2
    @Volatile var delay1 = 20L
    @Volatile var delay2 = 100L
    @Volatile var fakeTtl = 3
    @Volatile var isDiagnosticMode = false
    @Volatile var blockQuic = true
    @Volatile var isCharging = true

    // Circuit Breaker state
    private val circuitBreakers = ConcurrentHashMap<BypassStrategy, Long>()
    
    // Session Stickiness with TTL
    private val hostStrategyMemory = ConcurrentHashMap<String, Pair<BypassStrategy, Long>>()
    private val SESSION_TTL = 30 * 60 * 1000L // 30 minutes

    val isPanicMode: Boolean get() = _isPanicModeFlow.value

    init {
        HostCategory.entries.forEach { cat ->
            val catMap = ConcurrentHashMap<BypassStrategy, AtomicInteger>()
            BypassStrategy.entries.forEach { 
                catMap[it] = AtomicInteger(100)
            }
            strategyScores[cat] = catMap
        }
        BypassStrategy.entries.forEach {
            strategyStats[it] = StratStats()
        }
    }

    fun loadTuningSettings(context: Context) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
        isAutoTuning = prefs.getBoolean("is_auto_tuning", true)
        blockQuic = prefs.getBoolean("block_quic", true)
        isDiagnosticMode = prefs.getBoolean("is_diagnostic_mode", false)
        frag1 = prefs.getInt("frag1", 1)
        frag2 = prefs.getInt("frag2", 5)
        frag3 = prefs.getInt("frag3", 2)
        delay1 = prefs.getLong("delay1", 20L)
        delay2 = prefs.getLong("delay2", 100L)
        fakeTtl = prefs.getInt("fakeTtl", 3)
        val savedStrat = prefs.getString("global_strategy", BypassStrategy.SNI_SPLIT.name)
        try {
            _strategy.value = BypassStrategy.valueOf(savedStrat!!)
        } catch (e: Exception) {
            _strategy.value = BypassStrategy.SNI_SPLIT
        }
        
        val scorePrefs = context.getSharedPreferences("pink_proxy_scores", Context.MODE_PRIVATE)
        HostCategory.entries.forEach { cat ->
            BypassStrategy.entries.forEach { strat ->
                val legacyScore = scorePrefs.getInt("score_${strat.name}", 100)
                val score = scorePrefs.getInt("score_${cat.name}_${strat.name}", legacyScore)
                strategyScores[cat]?.get(strat)?.set(score)
            }
        }
    }

    fun saveTuningSettings(context: Context) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
        prefs.edit().apply {
            putBoolean("is_auto_tuning", isAutoTuning)
            putBoolean("block_quic", blockQuic)
            putBoolean("is_diagnostic_mode", isDiagnosticMode)
            putInt("frag1", frag1)
            putInt("frag2", frag2)
            putInt("frag3", frag3)
            putLong("delay1", delay1)
            putLong("delay2", delay2)
            putInt("fakeTtl", fakeTtl)
            putString("global_strategy", _strategy.value.name)
            apply()
        }
        saveScores(context)
    }

    fun saveScores(context: Context) {
        val prefs = context.getSharedPreferences("pink_proxy_scores", Context.MODE_PRIVATE)
        prefs.edit().apply {
            HostCategory.entries.forEach { cat ->
                strategyScores[cat]?.forEach { (strat, score) ->
                    putInt("score_${cat.name}_${strat.name}", score.get())
                }
            }
            apply()
        }
    }

    fun getBestStrategyForHost(host: String): BypassStrategy {
        if (!isAutoTuning) return _strategy.value
        
        val now = System.currentTimeMillis()
        val blacklisted = hostBlacklist[host]
        val cat = HostClassifier.classify(host)
        val scores = strategyScores[cat] ?: strategyScores[HostCategory.OTHER]!!
        
        val level = _censorshipLevel.value
        val preferredGroup = when {
            level > 75 -> StrategyGroup.EXTREME
            level > 50 -> StrategyGroup.HEAVY
            level > 25 -> StrategyGroup.MEDIUM
            else -> StrategyGroup.LIGHT
        }
        
        hostStrategyMemory[host]?.let { (remembered, expiry) ->
            if (now < expiry) {
                if (blacklisted?.get(remembered)?.let { now < it } == true) {
                    hostStrategyMemory.remove(host)
                } else if ((scores[remembered]?.get() ?: 0) > 40 && (circuitBreakers[remembered] ?: 0L) < now) {
                    return remembered
                }
            } else {
                hostStrategyMemory.remove(host)
            }
        }

        val entries = scores.entries.toList()
        val validEntries = entries.filter { entry ->
            val blacklistedUntil = blacklisted?.get(entry.key) ?: 0L
            val circuitBreakerUntil = circuitBreakers[entry.key] ?: 0L
            now >= blacklistedUntil && now >= circuitBreakerUntil
        }
        
        if (validEntries.isEmpty()) return BypassStrategy.CHAOS

        // Weighting by score AND strategy group relevance to censorship level
        val weightedEntries = validEntries.map { entry ->
            var weight = entry.value.get().coerceAtLeast(1).toDouble()
            
            // Apply minimum sample size protection: don't drop weight too fast if attempts are low
            val stats = strategyStats[entry.key] ?: StratStats()
            if (stats.successes.get() + stats.failures.get() < 5) {
                weight = weight.coerceAtLeast(80.0)
            }

            val group = strategyGrouping.entries.find { it.value.contains(entry.key) }?.key
            if (group == preferredGroup) weight *= 2.5
            else if (group == StrategyGroup.EXTREME && level < 30) weight *= 0.2 // Don't over-engineer simple cases
            
            val strat = entry.key
            // Adjust weight based on cost and risk according to network conditions
            if (level < 40) {
                // If censorship is low, penalize high cost and high risk strategies heavily
                weight /= (strat.cost + strat.risk).coerceAtLeast(1)
            } else {
                // If censorship is high, penalize cost slightly but allow high risk
                weight /= strat.cost.coerceAtLeast(1)
            }
            
            entry.key to weight
        }

        val totalWeight = weightedEntries.sumOf { it.second }
        var random = ThreadLocalRandom.current().nextDouble(totalWeight)
        for (entry in weightedEntries) {
            random -= entry.second
            if (random <= 0) {
                hostStrategyMemory[host] = entry.first to (now + SESSION_TTL)
                return entry.first
            }
        }
        val fallback = weightedEntries.maxByOrNull { it.second }?.first ?: BypassStrategy.SNI_SPLIT
        hostStrategyMemory[host] = fallback to (now + SESSION_TTL)
        return fallback
    }

    fun rotateGlobalStrategy() {
        val best = BypassStrategy.entries
            .filter { it != BypassStrategy.DIRECT }
            .maxByOrNull { strat ->
                HostCategory.entries.map { cat -> strategyScores[cat]?.get(strat)?.get() ?: 0 }.average()
            } ?: BypassStrategy.SNI_SPLIT
        _strategy.value = best
        ProxyStats.logRecovery("Strategy rotated to best: ${best.name}")
    }

    private var optimizerJob: Job? = null
    fun startAutonomousOptimizer(scope: CoroutineScope) {
        if (optimizerJob?.isActive == true) return
        optimizerJob = scope.launch {
            while (isActive) {
                delay(30000) // Every 30 seconds
                performSelfHealing()
                
                // Score Decay: Bring scores back towards 100 slowly
                HostCategory.entries.forEach { cat ->
                    strategyScores[cat]?.forEach { (_, score) ->
                        val current = score.get()
                        if (current < 100) score.addAndGet(1)
                        else if (current > 100) score.addAndGet(-1)
                    }
                }

                // Adaptive censorship level adjustment based on global success rate
                val currentRate = ProxyStats.getSuccessRate()
                if (currentRate < 60) {
                    _censorshipLevel.update { (it + 5).coerceAtMost(100) }
                } else if (currentRate > 90) {
                    _censorshipLevel.update { (it - 2).coerceAtLeast(0) }
                }
                
                // Periodic jitter and memory management
                if (ThreadLocalRandom.current().nextInt(100) < 15) {
                    ProxyStats.logRecovery("Optimizer: Fluctuating noise parameters for better entropy.")
                    frag1 = ThreadLocalRandom.current().nextInt(1, 3)
                    delay1 = ThreadLocalRandom.current().nextLong(10, 60)
                    
                    if (ThreadLocalRandom.current().nextBoolean()) {
                        val now = System.currentTimeMillis()
                        hostStrategyMemory.entries.removeIf { it.value.second < now }
                        
                        hostBlacklist.entries.removeIf { entry ->
                            entry.value.entries.removeIf { it.value < now }
                            entry.value.isEmpty()
                        }
                    }
                }
            }
        }
    }

    fun recordSuccess(strat: BypassStrategy, rtt: Long, host: String?) {
        ProxyStats.recordGlobalSuccess(rtt)
        if (rtt > 0) {
            TrafficShaper.updateRtt(rtt)
        }
        
        // Slowly decrease censorship level on success
        _censorshipLevel.update { (it - 1).coerceAtLeast(0) }
        
        val cat = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
        val scores = strategyScores[cat] ?: strategyScores[HostCategory.OTHER]!!
        
        scores[strat]?.addAndGet(if (rtt < 300) 10 else 5)?.let { 
            if (it > 1000) scores[strat]?.set(1000)
        }

        host?.let { 
            hostStrategyMemory[it] = strat to (System.currentTimeMillis() + SESSION_TTL)
            hostBlacklist[it]?.remove(strat)
        }
        
        strategyStats[strat]?.let { stats ->
            stats.successes.incrementAndGet()
            stats.totalRtt.addAndGet(rtt)
        }
        
        // Clear circuit breaker on success
        circuitBreakers.remove(strat)
    }

    fun recordSuccess(strat: BypassStrategy, rtt: Long, context: Context?) = recordSuccess(strat, rtt, null as String?)

    fun recordFailure(strat: BypassStrategy, host: String?) {
        ProxyStats.recordCensorshipEvent(true)
        
        // Increase censorship level on failure
        _censorshipLevel.update { (it + 5).coerceAtMost(100) }
        
        val cat = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
        val scores = strategyScores[cat] ?: strategyScores[HostCategory.OTHER]!!
        
        scores[strat]?.addAndGet(-25)?.let {
            if (it < 1) scores[strat]?.set(1)
        }
        
        host?.let { 
            if (hostStrategyMemory[it]?.first == strat) hostStrategyMemory.remove(it)
            
            val blacklist = hostBlacklist.getOrPut(it) { ConcurrentHashMap() }
            blacklist[strat] = System.currentTimeMillis() + 600000 // 10 min
        }
        
        strategyStats[strat]?.let { stats ->
            stats.failures.incrementAndGet()
            
            // Trip Circuit Breaker if failure rate is too high globally for this strategy
            val s = stats.successes.get()
            val f = stats.failures.get()
            if (f > 20 && s < f / 10) {
                ProxyStats.logRecovery("Circuit Breaker Tripped for ${strat.name}")
                circuitBreakers[strat] = System.currentTimeMillis() + 300000 // 5 min lockout
                stats.failures.set(0); stats.successes.set(0) // Reset stats for fresh start after lockout
            }
        }
    }

    fun recordFailure(strat: BypassStrategy, isCritical: Boolean, context: Context?) = recordFailure(strat, null as String?)

    fun performSelfHealing() {
        val rate = ProxyStats.getSuccessRate()
        if (rate < 40 && !isPanicMode) {
            panicOptimize()
        } else if (rate > 85 && isPanicMode) {
            _isPanicModeFlow.value = false
            ProxyStats.logRecovery("Stability restored: $rate%. Normal mode.")
        }
    }

    fun panicOptimize() {
        _isPanicModeFlow.value = true
        
        val oldMtu = _currentMtu.value
        val newMtu = if (oldMtu > 1300) 1280 else if (oldMtu > 1200) 1100 else 1000
        _currentMtu.value = newMtu
        
        ProxyStats.logRecovery("Panic Mode Active: MTU $oldMtu -> $newMtu. Attempting aggressive recovery.")
        
        rotateGlobalStrategy()
        hostStrategyMemory.clear()
        resetCaches()
        
        // Reset scores to give all strategies a fresh chance in new conditions
        HostCategory.entries.forEach { cat ->
            strategyScores[cat]?.forEach { (_, score) ->
                if (score.get() < 60) score.set(100)
            }
        }
        
        // Temporarily change frag parameters to force different packet boundaries
        frag1 = 1
        frag2 = ThreadLocalRandom.current().nextInt(2, 6)
        delay1 = 40
        
        ServiceChecker.runActiveProbing(null)
    }

    fun clearScores(context: Context) {
        val prefs = context.getSharedPreferences("pink_proxy_scores", Context.MODE_PRIVATE)
        prefs.edit().clear().apply()
        HostCategory.entries.forEach { cat ->
            BypassStrategy.entries.forEach { strategyScores[cat]?.get(it)?.set(100) }
        }
    }

    fun getSessionConfig(host: String, strategy: BypassStrategy, rtt: Long): SessionConfig {
        val rnd = ThreadLocalRandom.current()
        val cat = HostClassifier.classify(host)
        
        // Adaptive configuration with jitter to avoid fingerprints
        var f1 = (frag1 + rnd.nextInt(0, 3)).coerceAtLeast(1)
        var f2 = (frag2 + rnd.nextInt(0, 5)).coerceAtLeast(1)
        var f3 = (frag3 + rnd.nextInt(0, 10)).coerceAtLeast(1)
        var d1 = (delay1 + rnd.nextLong(0, 15)).coerceAtLeast(5)
        
        if (rtt > 250) {
            d1 = (d1 * 1.4).toLong()
        }
        
        when (cat) {
            HostCategory.STREAMING -> {
                f1 = (f1 * 3).coerceAtMost(120)
                f2 = (f2 * 2).coerceAtMost(200)
            }
            HostCategory.MESSENGER -> {
                d1 = (d1 * 0.7).toLong().coerceAtLeast(5)
            }
            HostCategory.AI -> {
                f1 = (f1 * 2).coerceAtMost(40)
            }
            HostCategory.FINANCE -> {
                d1 = (d1 * 1.5).toLong()
            }
            else -> {}
        }
        
        val ttl = if (fakeTtl == 0) rnd.nextInt(3, 8) else fakeTtl
        
        return SessionConfig(strategy, f1, f2, f3, d1, delay2, ttl)
    }
    
    fun getNetworkType() = _currentNetworkType.value
    
    fun getScore(strat: BypassStrategy) = strategyScores[HostCategory.OTHER]?.get(strat)?.get() ?: 0
    
    fun setStrategy(strat: BypassStrategy) {
        _strategy.value = strat
    }
    
    fun setGlobalStrategy(strat: BypassStrategy) = setStrategy(strat)

    fun recordStrategyResult(host: String, strategy: BypassStrategy, success: Boolean, avgDuration: Long = 50L) {
        if (success) {
            recordSuccess(strategy, avgDuration, host)
        } else {
            recordFailure(strategy, host)
        }
    }

    @Volatile var activeVpnService: VpnService? = null

    fun isHostCensored(host: String): Boolean {
        val h = host.lowercase(java.util.Locale.ROOT)
        return h.contains("youtube") || h.contains("googlevideo") || h.contains("ytimg") ||
               h.contains("facebook") || h.contains("instagram") || h.contains("twitter") ||
               h.contains("telegram") || h.contains("t.me") || h.contains("discord") ||
               h.contains("netflix") || h.contains("openai") || h.contains("chatgpt") ||
               h.contains("anthropic") || h.contains("medium.com") || h.contains("quora.com")
    }

    fun isHostDirect(host: String): Boolean {
        if (host.isEmpty()) return false
        val h = host.lowercase(java.util.Locale.ROOT)
        
        // Local addresses
        if (h == "localhost" || h == "127.0.0.1" || h == "::1") return true
        if (h.startsWith("10.") || h.startsWith("192.168.")) return true
        if (h.startsWith("172.") && h.length >= 7) {
            val secondOctet = h.substring(4, h.indexOf('.', 4)).toIntOrNull() ?: 0
            if (secondOctet in 16..31) return true
        }

        // Region specific or unblocked
        return h.endsWith(".ru") || h.endsWith(".by") || h.contains("yandex") || h.contains("vk.com") || h.contains("ok.ru")
    }
    
    fun reset() {
        _strategy.value = BypassStrategy.SNI_SPLIT
    }
    
    fun resetCaches() {
        hostStrategyMemory.clear()
        HostCategory.entries.forEach { cat ->
            BypassStrategy.entries.forEach { strategyScores[cat]?.get(it)?.set(100) }
        }
    }

    fun getStrategyMetrics(): List<StrategyMetric> {
        return BypassStrategy.entries.map { strat ->
            // Use weighted average score across categories or just OTHER as proxy
            val score = strategyScores[HostCategory.OTHER]?.get(strat)?.get() ?: 0
            val stats = strategyStats[strat] ?: StratStats()
            val s = stats.successes.get()
            val f = stats.failures.get()
            val t = stats.totalRtt.get()
            val avgRtt = if (s > 0) t / s else 0L
            StrategyMetric(strat, score, s, f, avgRtt)
        }.sortedByDescending { it.score }
    }

    object TrafficShaper {
        private var errorCounter = 0
        private var lastErrorTime = 0L

        fun recordError() {
            errorCounter++
            lastErrorTime = System.currentTimeMillis()
            if (errorCounter > 8) {
                ProxyStats.updateCongestionWindow(-5)
                // Heuristic: continuous errors might be MTU issues
                if (errorCounter > 20) {
                    val currentMtu = _currentMtu.value
                    if (currentMtu > 1200) {
                        _currentMtu.value = currentMtu - 50
                        ProxyStats.logRecovery("MTU Auto-tuning: $currentMtu -> ${_currentMtu.value} due to persistent errors.")
                    }
                }
                errorCounter = 0
            }
        }

        fun updateRtt(rtt: Long) {
            _currentRttMs.value = (_currentRttMs.value * 0.8 + rtt * 0.2).toLong()
            
            if (rtt < 100) {
                ProxyStats.updateCongestionWindow(2)
            } else if (rtt < 200) {
                ProxyStats.updateCongestionWindow(1)
            } else if (rtt > 500) {
                ProxyStats.updateCongestionWindow(-2)
            } else if (rtt > 1000) {
                ProxyStats.updateCongestionWindow(-5)
            }
            
            if (System.currentTimeMillis() - lastErrorTime > 30000) {
                errorCounter = 0
            }
        }
    }

    suspend fun applyBypass(socket: Socket, output: OutputStream, data: ByteArray, length: Int, config: SessionConfig, host: String) {
        val rnd = ThreadLocalRandom.current()
        val strategy = config.strategy
        
        if (strategy == BypassStrategy.DIRECT) {
            output.write(data, 0, length); output.flush(); return
        }

        if (length <= 5) {
            output.write(data, 0, length); output.flush(); return
        }

        try {
            socket.tcpNoDelay = true
        } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }

        when (strategy) {
            BypassStrategy.SNI_SPLIT -> {
                val offset = TlsParser.findSniOffset(data, length, host)
                val split = if (offset != -1) offset + 1 else config.frag1.coerceIn(1, length - 1)
                val safeSplit = split.coerceIn(1, length - 1)
                output.write(data, 0, safeSplit); output.flush(); delay(config.delay1)
                output.write(data, safeSplit, length - safeSplit); output.flush()
            }
            BypassStrategy.TLS_SNI_SYMMETRIC_SPLIT -> {
                val offset = TlsParser.findSniOffset(data, length, host)
                val split = if (offset != -1 && host.isNotEmpty()) offset + (host.length / 2) else config.frag1.coerceIn(1, length - 1)
                val safeSplit = split.coerceIn(1, length - 1)
                output.write(data, 0, safeSplit); output.flush(); delay(config.delay1)
                output.write(data, safeSplit, length - safeSplit); output.flush()
            }
            BypassStrategy.SNI_TRIPLE -> {
                val offset = TlsParser.findSniOffset(data, length, host)
                if (offset != -1 && length > offset + host.length + 1) {
                    val part1 = (host.length / 3).coerceAtLeast(1)
                    val part2 = (2 * host.length / 3).coerceAtLeast(part1 + 1)
                    
                    val s1 = offset + part1
                    val s2 = offset + part2
                    
                    output.write(data, 0, s1); output.flush(); delay(config.delay1)
                    output.write(data, s1, s2 - s1); output.flush(); delay(config.delay2)
                    output.write(data, s2, length - s2); output.flush()
                } else {
                    val s1 = (length / 3).coerceIn(1, length - 2)
                    val s2 = (2 * length / 3).coerceIn(s1 + 1, length - 1)
                    output.write(data, 0, s1); output.flush(); delay(config.delay1)
                    output.write(data, s1, s2 - s1); output.flush(); delay(config.delay2)
                    output.write(data, s2, length - s2); output.flush()
                }
            }
            BypassStrategy.FAKE_PACKET -> {
                val fake = FakePacketHelper.buildFakeClientHello(host, rnd.nextInt(40, 91))
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(fake); output.flush()
                delay(config.delay1); TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_GREASE -> {
                if (length > 0 && data[0] == 0x16.toByte()) {
                    val fakeClientHello = FakePacketHelper.buildFakeClientHello(host, rnd.nextInt(40, 90))
                    TtlHelper.setTtl(socket, config.fakeTtl); output.write(fakeClientHello); output.flush()
                    delay(config.delay1); TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_OOB_DESYNC -> {
                try { socket.sendUrgentData(0xFF) } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.WINDOW_SIZE -> {
                var pos = 0; val chunkSize = rnd.nextInt(1, 5)
                while (pos < length) {
                    val size = chunkSize.coerceAtMost(length - pos)
                    output.write(data, pos, size); output.flush(); pos += size; delay(1)
                }
            }
            BypassStrategy.FRAGMENT_MULTI -> {
                var pos = 0
                while (pos < length) {
                    val size = (config.frag3 + rnd.nextInt(-1, 2)).coerceIn(1, 10).coerceAtMost(length - pos)
                    output.write(data, pos, size); output.flush(); pos += size; if (pos < length) delay(rnd.nextLong(1, 15))
                }
            }
            BypassStrategy.TLS_DIRTY -> {
                if (length > 5 && data[0] == 0x16.toByte()) {
                    val dirty = data.copyOf()
                    if (length > 10) dirty[9] = (dirty[9].toInt() xor 0xFF).toByte()
                    TtlHelper.setTtl(socket, config.fakeTtl); output.write(dirty); output.flush()
                    delay(config.delay1); TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_PAD -> {
                output.write(data, 0, length); output.flush()
                val pad = ByteArray(rnd.nextInt(100, 500)) { 0 }
                output.write(pad); output.flush()
            }
            BypassStrategy.SLOW_SEND -> {
                for (i in 0 until length) {
                    output.write(data[i].toInt()); output.flush()
                    if (i < length - 1) delay(rnd.nextLong(1, 5))
                }
            }
            BypassStrategy.SNI_MANGLE -> {
                val offset = TlsParser.findSniOffset(data, length, host)
                if (offset != -1 && offset < length) {
                    val mangled = data.copyOf(); val hostLen = host.length.coerceAtMost(32)
                    for (i in 0 until hostLen) {
                        if (offset + i >= length) break
                        if (rnd.nextBoolean()) {
                            val char = mangled[offset + i].toInt().toChar()
                            if (char in 'a'..'z') mangled[offset + i] = (char - 32).code.toByte()
                            else if (char in 'A'..'Z') mangled[offset + i] = (char + 32).code.toByte()
                        }
                    }
                    val split = offset + rnd.nextInt(1, hostLen.coerceAtLeast(2))
                    val safeSplit = split.coerceIn(1, length - 1)
                    output.write(mangled, 0, safeSplit); output.flush(); delay(config.delay1)
                    output.write(mangled, safeSplit, length - safeSplit); output.flush()
                } else {
                    val split = config.frag1.coerceIn(1, length - 1)
                    output.write(data, 0, split); output.flush(); delay(config.delay1); output.write(data, split, length - split); output.flush()
                }
            }
            BypassStrategy.TLS_MULTI_FRAG -> {
                var pos = 0
                while (pos < length) {
                    val size = rnd.nextInt(1, 10).coerceAtMost(length - pos)
                    output.write(data, pos, size); output.flush(); pos += size; if (pos < length) delay(rnd.nextLong(1, 5))
                }
            }
            BypassStrategy.GHOST_PACKETS -> {
                repeat(rnd.nextInt(1, 3)) {
                    val ghost = ByteArray(rnd.nextInt(10, 100)); rnd.nextBytes(ghost)
                    TtlHelper.setTtl(socket, config.fakeTtl); output.write(ghost); output.flush(); delay(rnd.nextLong(10, 50))
                }
                TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_REC_SPLIT -> {
                if (length > 5 && data[0] == 0x16.toByte() && data[1] == 0x03.toByte()) {
                    output.write(data, 0, 5); output.flush(); delay(rnd.nextLong(5, 20))
                    output.write(data, 5, length - 5); output.flush()
                } else {
                    val split = 1; output.write(data, 0, split); output.flush(); delay(5)
                    output.write(data, split, length - split); output.flush()
                }
            }
            BypassStrategy.HTTP_HOST_SPACE -> {
                val s = String(data, 0, length)
                if (s.contains("Host:", ignoreCase = true)) {
                    val modified = s.replace("Host:", "Host: ", ignoreCase = true)
                    output.write(modified.toByteArray()); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_MSS_CLAMP -> {
                val clampSize = 536; var offset = 0
                while (offset < length) {
                    val chunk = minOf(clampSize, length - offset)
                    output.write(data, offset, chunk); output.flush(); offset += chunk; delay(2)
                }
            }
            BypassStrategy.HTTP_AUTH_RANDOM -> {
                val s = String(data, 0, length)
                if (s.contains("HTTP/")) {
                    val fakeAuth = "Authorization: Basic " + java.util.Base64.getEncoder().encodeToString("fake:fake".toByteArray()) + "\r\n"
                    val modified = s.replaceFirst("\r\n", "\r\n$fakeAuth")
                    output.write(modified.toByteArray()); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_HEADER_FUZZING -> {
                val s = String(data, 0, length)
                if (s.contains("HTTP/")) {
                    val junkHeader = "X-Fuzz-Value: ${java.util.UUID.randomUUID()}\r\n"
                    val modified = s.replaceFirst("\r\n", "\r\n$junkHeader")
                    output.write(modified.toByteArray()); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_METHOD_FAKE -> {
                if (length > 5 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val raw = String(data, 0, length)
                    val mod = when {
                        raw.startsWith("GET ") -> "gEt " + raw.substring(4)
                        raw.startsWith("POST ") -> "pOsT " + raw.substring(5)
                        raw.startsWith("HEAD ") -> "hEaD " + raw.substring(5)
                        else -> raw
                    }
                    output.write(mod.toByteArray())
                } else { output.write(data, 0, length) }
                output.flush()
            }
            BypassStrategy.HTTP_USER_AGENT_SKEW -> {
                val s = String(data, 0, length)
                if (s.contains("User-Agent:", ignoreCase = true)) {
                    val modified = s.replace(Regex("User-Agent:.*?\r\n", RegexOption.IGNORE_CASE), "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n")
                    output.write(modified.toByteArray()); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.OOB_DESYNC -> {
                val split = rnd.nextInt(1, length.coerceAtMost(5))
                output.write(data, 0, split); output.flush()
                try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                delay(config.delay1); output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.TCP_ZERO_WINDOW -> {
                var pos = 0
                while (pos < length) {
                    val size = rnd.nextInt(1, 15).coerceAtMost(length - pos)
                    output.write(data, pos, size); output.flush(); pos += size; if (pos < length) delay(rnd.nextLong(10, 80))
                }
            }
            BypassStrategy.HTTP_RANGE_SKEW -> {
                val s = String(data, 0, length)
                if (s.startsWith("GET ") || s.startsWith("POST ")) {
                    val fakeRange = "Range: bytes=0-\r\n"
                    val modified = s.replaceFirst("\r\n", "\r\n$fakeRange")
                    output.write(modified.toByteArray()); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_VERSION_SKEW -> {
                val s = String(data, 0, length)
                if (s.contains("HTTP/1.1")) {
                    val modified = s.replaceFirst("HTTP/1.1", "HTTP/1.2")
                    output.write(modified.toByteArray()); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_REHANDSHAKE_FAKE -> {
                output.write(data, 0, length); output.flush(); delay(config.delay1)
                val helloReq = byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00)
                output.write(helloReq); output.flush()
            }
            BypassStrategy.TLS_HELLO_JUNK -> {
                val junk = ByteArray(rnd.nextInt(10, 40)) { rnd.nextInt(0, 256).toByte() }
                output.write(junk); output.flush(); delay(config.delay1)
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TCP_WINDOW_SIZE_CHAOS -> {
                var pos = 0
                while (pos < length) {
                    val chunkSize = rnd.nextInt(1, 15)
                    val size = chunkSize.coerceAtMost(length - pos)
                    output.write(data, pos, size); output.flush(); pos += size; delay(rnd.nextLong(1, 10))
                }
            }
            BypassStrategy.TCP_URG_SKEW, BypassStrategy.TCP_URGENT_RANDOM -> {
                try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_SNI_SKEW -> {
                if (length > 0 && data[0] == 0x16.toByte()) {
                    val fakeClientHello = FakePacketHelper.buildFakeClientHello(host, rnd.nextInt(50, 100), noMangle = false)
                    val split = rnd.nextInt(20, fakeClientHello.size.coerceAtLeast(30))
                    TtlHelper.setTtl(socket, config.fakeTtl); output.write(fakeClientHello, 0, split); output.flush()
                    delay(config.delay1); output.write(fakeClientHello, split, fakeClientHello.size - split); output.flush()
                    delay(5); TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_EXT_SKEW -> {
                val offset = TlsParser.findSniOffset(data, length, host)
                val split = if (offset != -1) offset + 2 else (length / 2).coerceAtLeast(1)
                val safeSplit = split.coerceIn(1, length - 1)
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(data, 0, safeSplit); output.flush()
                delay(config.delay1); TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TCP_FAST_RETRANSMIT_SIM -> {
                val firstChunk = rnd.nextInt(1, 5).coerceAtMost(length - 1)
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(data, 0, firstChunk); output.flush()
                delay(2); TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_REC_MANGLE -> {
                if (length > 10 && data[0] == 0x16.toByte() && data[1] == 0x03.toByte()) {
                    val halfPayload = (length - 5) / 2
                    if (halfPayload > 0) {
                        output.write(data[0].toInt()); output.write(data[1].toInt()); output.write(data[2].toInt())
                        output.write((halfPayload shr 8) and 0xFF); output.write(halfPayload and 0xFF)
                        output.write(data, 5, halfPayload); output.flush(); delay(config.delay1)
                        val remLen = length - 5 - halfPayload
                        output.write(data[0].toInt()); output.write(data[1].toInt()); output.write(data[2].toInt())
                        output.write((remLen shr 8) and 0xFF); output.write(remLen and 0xFF)
                        output.write(data, 5 + halfPayload, remLen); output.flush()
                    } else { output.write(data, 0, length); output.flush() }
                } else {
                    val split = (length / 2).coerceIn(1, length - 1)
                    output.write(data, 0, split); output.flush(); delay(config.delay1)
                    output.write(data, split, length - split); output.flush()
                }
            }
            BypassStrategy.TCP_REORDER_SIM -> {
                val split = (length / 2).coerceIn(1, length - 1)
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(data, split, length - split); output.flush()
                delay(2); TtlHelper.setTtl(socket, 64); output.write(data, 0, split); output.flush()
                delay(2); output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.TCP_FAST_OPEN_FAKE -> {
                val cookie = byteArrayOf(0x01, 0x02, 0x03, 0x04)
                output.write(cookie); output.flush(); delay(config.delay1); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_PADDING_RAND -> {
                output.write(data, 0, length); output.flush()
                val padSize = rnd.nextInt(16, 128); val pad = ByteArray(padSize) { rnd.nextInt(256).toByte() }
                output.write(pad); output.flush()
            }
            BypassStrategy.TCP_RST_FAKE -> {
                val rstPayload = byteArrayOf(0x52, 0x53, 0x54, 0x00, 0x00, 0x00)
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(rstPayload); output.flush()
                delay(2); TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TCP_TIMESTAMP_MANGLE -> {
                try { socket.sendUrgentData(rnd.nextInt(1, 255)) } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                val split = (length / 3).coerceIn(1, length - 1)
                output.write(data, 0, split); output.flush(); delay(config.delay1)
                output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.TLS_CIPHER_SHUFFLE -> {
                val fake = FakePacketHelper.buildFakeClientHello(host, rnd.nextInt(40, 80))
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(fake); output.flush()
                delay(config.delay1); TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_ALPN_SKEW -> {
                val fake = FakePacketHelper.buildFakeClientHello(host, rnd.nextInt(30, 70))
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(fake); output.flush()
                delay(config.delay1); TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_EXTENSION_GREASE -> {
                val fake = FakePacketHelper.buildFakeClientHello(host, rnd.nextInt(50, 100))
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(fake); output.flush()
                delay(config.delay1); TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TCP_REORDER_CHAOS -> {
                val p1 = length / 3; val p2 = 2 * length / 3
                output.write(data, p2, length - p2); output.flush(); delay(10)
                output.write(data, p1, p2 - p1); output.flush(); delay(10)
                output.write(data, 0, p1); output.flush()
            }
            BypassStrategy.TLS_LEGACY_HELLOS -> {
                val hello = FakePacketHelper.buildFakeClientHello(host, 60)
                if (hello.size > 10) { hello[1] = 0x03; hello[2] = 0x01; hello[9] = 0x03; hello[10] = 0x01 }
                output.write(hello); output.flush()
            }
            BypassStrategy.TCP_KEEP_ALIVE_FAKE -> {
                output.write(data, 0, length); output.flush()
                repeat(3) { delay(30); output.write(byteArrayOf(0x00)); output.flush() }
            }
            BypassStrategy.HTTP_HOST_CASE_MANGLE -> {
                val s = String(data, 0, length); val mod = s.replace("Host: ", "hOsT: ")
                output.write(mod.toByteArray()); output.flush()
            }
            BypassStrategy.TLS_SESSION_TICKET_SKEW -> {
                val hello = FakePacketHelper.buildFakeClientHello(host, rnd.nextInt(100, 200))
                output.write(hello); output.flush(); delay(config.delay1)
                output.write(byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x20) + ByteArray(32) { 0x00.toByte() }); output.flush()
            }
            BypassStrategy.TLS_MULTI_SNI -> {
                val hello = FakePacketHelper.buildMultiSniHello(host)
                output.write(hello); output.flush(); delay(config.delay1); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.HTTP2_PREAMBLE_FAKE -> {
                val preamble = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                output.write(preamble.toByteArray()); output.flush(); delay(10)
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.HTTP_CHUNKED_FAKE -> {
                val s = String(data, 0, length)
                if (s.contains("HTTP/")) {
                    val mod = s.replace("HTTP/1.1\r\n", "HTTP/1.1\r\nTransfer-Encoding: chunked\r\n")
                    output.write(mod.toByteArray()); output.flush(); delay(10); output.write("0\r\n\r\n".toByteArray()); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_WINDOW_RESTRICT -> {
                socket.sendBufferSize = 512; output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_MIXED_CASE_SNI -> {
                val mixedHost = host.map { if (java.util.concurrent.ThreadLocalRandom.current().nextBoolean()) it.uppercaseChar() else it.lowercaseChar() }.joinToString("")
                val hello = FakePacketHelper.buildFakeClientHello(mixedHost, rnd.nextInt(50, 100))
                output.write(hello); output.flush(); delay(config.delay1)
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_0RTT_FAKE -> {
                val hello = FakePacketHelper.buildTls13Hello(host)
                val earlyData = ByteArray(rnd.nextInt(50, 200)) { rnd.nextInt(256).toByte() }
                output.write(hello); output.flush(); delay(5)
                output.write(earlyData); output.flush(); delay(config.delay1)
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_COMPRESSION_FAKE -> {
                val hello = FakePacketHelper.buildFakeClientHello(host, rnd.nextInt(50, 100))
                if (hello.size > 40) { hello[hello.size - 5] = 0x02; hello[hello.size - 4] = 0x01; hello[hello.size - 3] = 0x00 }
                output.write(hello); output.flush(); delay(config.delay1); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_ECH_FAKE -> {
                val hello = FakePacketHelper.buildFakeClientHello(host, rnd.nextInt(40, 80))
                val ech = ByteArray(rnd.nextInt(64, 128)) { rnd.nextInt(256).toByte() }
                output.write(hello)
                output.write(byteArrayOf(0xfe.toByte(), 0x0d.toByte(), (ech.size shr 8).toByte(), (ech.size and 0xFF).toByte()))
                output.write(ech); output.flush(); delay(config.delay1); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TCP_WINDOW_SCAN -> {
                val step = (length / 4).coerceAtLeast(1); var pos = 0; val windows = listOf(512, 1024, 2048, 4096); var wIdx = 0
                while (pos < length) {
                    socket.sendBufferSize = windows[wIdx % windows.size]
                    val size = step.coerceAtMost(length - pos); output.write(data, pos, size); output.flush()
                    pos += size; wIdx++; if (pos < length) delay(10)
                }
            }
            BypassStrategy.HTTP_PIPELINE_FAKE -> {
                if (length > 10 && data[0] == 'G'.code.toByte()) {
                    val fake = "GET /favicon.ico HTTP/1.1\r\nHost: ${host}\r\nConnection: keep-alive\r\n\r\n"
                    output.write(fake.toByteArray()); output.flush(); delay(config.delay1); output.write(data, 0, length)
                } else { output.write(data, 0, length) }
                output.flush()
            }
            BypassStrategy.HTTP_OOB_INJECT -> {
                val s = String(data, 0, length, Charsets.US_ASCII)
                if (s.contains("Host:", ignoreCase = true)) {
                    val idx = s.indexOf("Host:", ignoreCase = true)
                    output.write(data, 0, idx)
                    output.flush()
                    socket.sendUrgentData('X'.code)
                    delay(config.delay1)
                    output.write(data, idx, length - idx)
                } else {
                    output.write(data, 0, length)
                }
                output.flush()
            }
            BypassStrategy.TCP_FRAG_OOB -> {
                if (length > 5) {
                    val split = length / 2
                    output.write(data, 0, split)
                    output.flush()
                    socket.sendUrgentData('!'.code)
                    delay(config.delay1)
                    output.write(data, split, length - split)
                } else {
                    output.write(data, 0, length)
                }
                output.flush()
            }
            BypassStrategy.TLS_CHROME_HELLO_FAKE -> {
                val fake = FakePacketHelper.buildChromeHello(host)
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(fake); output.flush()
                delay(config.delay1); TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_FIREFOX_HELLO_FAKE -> {
                val fake = FakePacketHelper.buildFirefoxHello(host)
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(fake); output.flush()
                delay(config.delay1); TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_13_HELLO_FAKE -> {
                val fake = FakePacketHelper.buildTls13Hello(host)
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(fake); output.flush()
                delay(config.delay1); TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TCP_REORDER_DESYNC -> {
                if (length > 10) {
                    val split = length / 2
                    // Send second half first with low TTL
                    TtlHelper.setTtl(socket, config.fakeTtl)
                    output.write(data, split, length - split); output.flush(); delay(config.delay1)
                    // Send first half with normal TTL
                    TtlHelper.setTtl(socket, 64)
                    output.write(data, 0, split); output.flush(); delay(2)
                    // Send second half with normal TTL
                    output.write(data, split, length - split); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_SESSION_ID_RAND -> {
                if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                    val mangled = data.copyOf()
                    val sidLen = mangled[43].toInt() and 0xFF
                    if (sidLen > 0 && 44 + sidLen <= length) {
                        for (i in 0 until sidLen) mangled[44 + i] = rnd.nextInt(256).toByte()
                    }
                    output.write(mangled); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_ACK_DELAY -> {
                var pos = 0
                while (pos < length) {
                    val size = rnd.nextInt(1, 10).coerceAtMost(length - pos)
                    output.write(data, pos, size); output.flush(); pos += size
                    if (pos < length) delay(rnd.nextLong(10, 50))
                }
            }
            BypassStrategy.TLS_GREASE_SKEW -> {
                val grease = byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00)
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(grease); output.flush()
                delay(config.delay1); TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.ADAPTIVE_CHUNK -> {
                var offset = 0
                while (offset < length) {
                    val chunkSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 10).coerceAtMost(length - offset)
                    output.write(data, offset, chunkSize); output.flush()
                    delay(java.util.concurrent.ThreadLocalRandom.current().nextLong(5, 20))
                    offset += chunkSize
                }
            }
            BypassStrategy.DNS_OVER_TCP -> {
                val prefix = byteArrayOf(0, length.toByte())
                output.write(prefix); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.DNS_CASE_MANGLE -> {
                // Simple case mangling (very naive)
                val mod = data.clone()
                for (i in 0 until length) {
                    if (mod[i] >= 65 && mod[i] <= 90) mod[i] = (mod[i] + 32).toByte()
                    else if (mod[i] >= 97 && mod[i] <= 122 && java.util.concurrent.ThreadLocalRandom.current().nextBoolean()) mod[i] = (mod[i] - 32).toByte()
                }
                output.write(mod, 0, length); output.flush()
            }
            BypassStrategy.QUIC_MTU_PROBE -> {
                output.write(data, 0, length); output.flush()
                repeat(5) { delay(10); output.write(ByteArray(1200) { 0 }); output.flush() }
            }
            BypassStrategy.PROTOCOL_CONFUSION_SSH -> {
                val fake = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n".toByteArray()
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(fake); output.flush()
                delay(config.delay1); TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.PROTOCOL_CONFUSION_BITTORRENT -> {
                val fake = ByteArray(68)
                fake[0] = 19.toByte()
                System.arraycopy("BitTorrent protocol".toByteArray(), 0, fake, 1, 19)
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(fake); output.flush()
                delay(config.delay1); TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TCP_TOS_MANGLE -> {
                try { socket.trafficClass = 0x08 } catch (e: Exception) {}
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.CHAOS -> {
                val strat = BypassStrategy.entries.filter { it != BypassStrategy.CHAOS && it != BypassStrategy.DIRECT }.random()
                applyBypass(socket, output, data, length, config.copy(strategy = strat), host)
            }
            else -> {
                val split = 1; output.write(data, 0, split); output.flush(); delay(5)
                output.write(data, split, length - split); output.flush()
            }
        }
    }
}

