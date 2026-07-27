package com.aistudio.pinkproxy.fresh

import android.content.Context
import android.net.VpnService
import android.util.Log
import androidx.core.content.edit
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
    private val HTTP_1_1_CRLF = byteArrayOf('H'.code.toByte(), 'T'.code.toByte(), 'T'.code.toByte(), 'P'.code.toByte(), '/'.code.toByte(), '1'.code.toByte(), '.'.code.toByte(), '1'.code.toByte(), '\r'.code.toByte(), '\n'.code.toByte())
    private val RST_PAYLOAD = byteArrayOf(0x52, 0x53, 0x54, 0x00, 0x00, 0x00)
    private val TLS_SESSION_TICKET = byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x20) + ByteArray(32) { 0x00.toByte() }
    private val GREASE_BYTES = byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00)
    private val TLS_HELLO_REQ = byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00)
    private val USER_AGENT_REGEX = Regex("User-Agent:.*?\r\n", RegexOption.IGNORE_CASE)
    private val CRLF_BYTES = byteArrayOf('\r'.code.toByte(), '\n'.code.toByte())
    private val END_CHUNK_BYTES = byteArrayOf('0'.code.toByte(), '\r'.code.toByte(), '\n'.code.toByte(), '\r'.code.toByte(), '\n'.code.toByte())
    private val CHUNK_HEADERS = Array(4097) { "${it.toString(16)}\r\n".toByteArray() }
    
    private val FAKE_AUTH_HEADER = "Authorization: Basic ZmFrZTpmYWtl\r\n".toByteArray()
    private val FAKE_RANGE_HEADER = "Range: bytes=0-\r\n".toByteArray()
    private val SPOOFED_USER_AGENT = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n".toByteArray()

    private val HTTP2_PREAMBLE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray()

    private val _strategy = MutableStateFlow(BypassStrategy.SNI_SPLIT)
    val strategy: StateFlow<BypassStrategy> = _strategy.asStateFlow()
    
    private val _censorshipLevel = ProxyStats.censorshipIntensity
    val censorshipLevel: StateFlow<Int> = _censorshipLevel

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
    @Volatile var preferIpv6 = false

    // Circuit Breaker state
    private val circuitBreakers = ConcurrentHashMap<BypassStrategy, Long>()
    private val BREAKER_TTL = 5 * 60 * 1000L // 5 minutes
    
    // Session Stickiness with TTL
    private val hostStrategyMemory = ConcurrentHashMap<String, Pair<BypassStrategy, Long>>()
    private val SESSION_TTL = 30 * 60 * 1000L // 30 minutes

    val isPanicMode: Boolean get() = _isPanicModeFlow.value
    fun setPanicMode(enabled: Boolean) {
        _isPanicModeFlow.value = enabled
    }

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

    fun setMtu(mtu: Int) {
        _currentMtu.value = mtu.coerceIn(576, 1500)
        Log.i("BypassConfig", "MTU set to ${_currentMtu.value}")
    }

    fun updateNetworkType(type: NetworkType) {
        if (_currentNetworkType.value != type) {
            _currentNetworkType.value = type
            Log.i("BypassConfig", "Network type updated: $type. Clearing session memory.")
            hostStrategyMemory.clear() // Network changed, old strategies might not be optimal
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
        prefs.edit {
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
        }
        saveScores(context)
    }

    fun saveScores(context: Context) {
        val prefs = context.getSharedPreferences("pink_proxy_scores", Context.MODE_PRIVATE)
        prefs.edit {
            HostCategory.entries.forEach { cat ->
                strategyScores[cat]?.forEach { (strat, score) ->
                    putInt("score_${cat.name}_${strat.name}", score.get())
                }
            }
        }
    }

    fun loadScores(context: Context) {
        val prefs = context.getSharedPreferences("pink_proxy_scores", Context.MODE_PRIVATE)
        HostCategory.entries.forEach { cat ->
            strategyScores[cat]?.forEach { (strat, score) ->
                val saved = prefs.getInt("score_${cat.name}_${strat.name}", 100)
                score.set(saved)
            }
        }
        Log.i("BypassConfig", "Loaded strategy scores from persistence.")
    }

    fun getBestStrategyForHost(host: String): BypassStrategy {
        if (!isAutoTuning) return _strategy.value
        
        val now = System.currentTimeMillis()
        val blacklisted = hostBlacklist[host]
        val cat = HostClassifier.classify(host)
        
        if (cat == HostCategory.AD) return BypassStrategy.TCP_RST_FAKE // Block ads

        val scores = strategyScores[cat] ?: strategyScores[HostCategory.OTHER]!!
        
        val level = _censorshipLevel.value
        val preferredGroup = when {
            level > 75 -> StrategyGroup.EXTREME
            level > 50 -> StrategyGroup.HEAVY
            level > 25 -> StrategyGroup.MEDIUM
            else -> StrategyGroup.LIGHT
        }
        
        val dpiType = ProxyStats.currentDpiType.value
        val jitter = ProxyStats.jitter.value
        
        hostStrategyMemory[host]?.let { (remembered, expiry) ->
            if (now < expiry) {
                if (blacklisted?.get(remembered)?.let { now < it } == true) {
                    hostStrategyMemory.remove(host)
                } else {
                    val baseScore = scores[remembered]?.get() ?: 0
                    var boostedScore = baseScore
                    when (dpiType) {
                        DpiType.TCP_RESET -> {
                            if (remembered.family == StrategyFamily.TCP) boostedScore += 40
                            if (remembered == BypassStrategy.FAKE_PACKET || remembered == BypassStrategy.TCP_OOB_DESYNC) boostedScore += 50
                        }
                        DpiType.CONNECTION_TIMEOUT -> {
                            if (remembered == BypassStrategy.TLS_CLIENT_HELLO_CHOP || remembered == BypassStrategy.FRAGMENT_MULTI) boostedScore += 40
                            if (remembered == BypassStrategy.TCP_ZERO_WINDOW) boostedScore += 30
                        }
                        DpiType.TLS_SNI_BLOCK -> {
                            if (remembered.family == StrategyFamily.TLS || remembered.family == StrategyFamily.FRAGMENTATION) boostedScore += 50
                            if (remembered == BypassStrategy.SNI_SPLIT || remembered == BypassStrategy.TLS_SNI_SKEW) boostedScore += 60
                        }
                        DpiType.HTTP_BLOCK -> {
                            if (remembered.family == StrategyFamily.HTTP) boostedScore += 50
                            if (remembered == BypassStrategy.HTTP_HOST_MANGLE || remembered == BypassStrategy.HTTP_FRAGMENT) boostedScore += 60
                        }
                        else -> {}
                    }
                    if (jitter > 100 && (remembered == BypassStrategy.TLS_CLIENT_HELLO_CHOP || remembered == BypassStrategy.HTTP_FRAGMENT)) {
                        boostedScore += 20
                    }
                    if (boostedScore > 40 && (circuitBreakers[remembered] ?: 0L) < now) {
                        return remembered
                    }
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

            // Category-specific weights
            when (cat) {
                HostCategory.STREAMING -> {
                    if (entry.key.family == StrategyFamily.FRAGMENTATION) weight *= 1.5
                    if (entry.key == BypassStrategy.WINDOW_SIZE) weight *= 2.0
                }
                HostCategory.MESSENGER -> {
                    if (entry.key.family == StrategyFamily.UDP || entry.key == BypassStrategy.QUIC_INITIAL_FAKE || entry.key == BypassStrategy.UDP_HIGH_VOL_PACING) weight *= 2.0
                }
                HostCategory.SOCIAL -> {
                    if (entry.key.family == StrategyFamily.TLS || entry.key.family == StrategyFamily.FRAGMENTATION || entry.key == BypassStrategy.TLS_RECORD_PADDING) weight *= 1.8
                }
                HostCategory.AI -> {
                    if (entry.key.family == StrategyFamily.TLS || entry.key == BypassStrategy.TLS_SNI_SKEW) weight *= 1.7
                }
                else -> {}
            }
            
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
    fun startAutonomousOptimizer(scope: CoroutineScope, context: Context) {
        if (optimizerJob?.isActive == true) return
        loadScores(context)
        optimizerJob = scope.launch {
            var saveCounter = 0
            while (isActive) {
                delay(30000) // Every 30 seconds
                performSelfHealing()
                
                saveCounter++
                if (saveCounter % 10 == 0) saveScores(context) // Every 5 minutes
                
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
                    ProxyStats.recordCensorshipEvent(true)
                } else if (currentRate > 90) {
                    ProxyStats.recordCensorshipEvent(false)
                }

                // Dynamic MTU adjustment based on stability
                val stability = ProxyStats.stabilityScore.value
                if (stability < 60 && _currentMtu.value > 1200) {
                    _currentMtu.value = 1100
                    ProxyStats.logRecovery("Stability drop detected. Reducing MTU to 1100.")
                } else if (stability > 90 && _currentMtu.value < 1400) {
                    _currentMtu.value = 1400
                }
                
                // IP Version Preference: If stability is low, try flipping IPv6 preference
                if (stability < 40 && currentRate < 40) {
                     preferIpv6 = !preferIpv6
                     ProxyStats.logRecovery("Switching IPv6 preference to $preferIpv6 due to high failure rate.")
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
        ProxyStats.recordCensorshipEvent(false)
        
        val cat = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
        val scores = strategyScores[cat] ?: strategyScores[HostCategory.OTHER]!!
        
        scores[strat]?.addAndGet(if (rtt < 300) 10 else 5)?.let { 
            if (it > 1000) scores[strat]?.set(1000)
        }

        host?.let { 
            hostStrategyMemory[it] = strat to (System.currentTimeMillis() + SESSION_TTL)
            if (hostStrategyMemory.size > 2000) {
                val oldest = hostStrategyMemory.entries.minByOrNull { it.value.second }
                if (oldest != null) hostStrategyMemory.remove(oldest.key)
            }
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

    fun recordDpiFailure(strat: BypassStrategy, host: String?, type: DpiType) {
        recordFailure(strat, host)
        ProxyStats.recordDpiEvent(type)
        
        when (type) {
            DpiType.DNS_POISONING -> {
                DnsCacheManager.clear()
                DnsOptimizer.forceRefresh()
            }
            DpiType.TCP_RESET -> {
                // Heuristic: if TCP Reset is detected, prioritize strategies that use fake packets or desync
                val cat = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
                val scores = strategyScores[cat] ?: strategyScores[HostCategory.OTHER]!!
                listOf(BypassStrategy.FAKE_PACKET, BypassStrategy.TCP_OOB_DESYNC, BypassStrategy.SNI_SPLIT).forEach {
                    scores[it]?.addAndGet(15)
                }
            }
            DpiType.CONNECTION_TIMEOUT -> {
                // If timeout, maybe lower MTU and try simpler strategies
                if (ProxyStats.censorshipIntensity.value > 50) {
                    _currentMtu.update { (it - 50).coerceAtLeast(1000) }
                }
            }
            else -> {}
        }
    }

    fun recordFailure(strat: BypassStrategy, host: String?) {
        ProxyStats.recordCensorshipEvent(true)
        
        val stats = strategyStats[strat]
        stats?.failures?.incrementAndGet()

        // Circuit Breaker: if strategy fails too much globally, disable it for a while
        if ((stats?.failures?.get() ?: 0) % 5 == 0L) {
             val successes = stats?.successes?.get() ?: 0
             val failures = stats?.failures?.get() ?: 0
             val total = (successes + failures).coerceAtLeast(1)
             val failRate = failures.toDouble() / total
             if (failRate > 0.7) {
                 circuitBreakers[strat] = System.currentTimeMillis() + 300000L
                 Log.w("BypassConfig", "Circuit Breaker: strategy $strat is now blacklisted for 5 minutes")
             }
        }
        
        val cat = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
        val scores = strategyScores[cat] ?: strategyScores[HostCategory.OTHER]!!
        
        scores[strat]?.addAndGet(-25)?.let {
            if (it < 1) scores[strat]?.set(1)
        }
        
        host?.let { 
            if (hostStrategyMemory[it]?.first == strat) hostStrategyMemory.remove(it)
            
            val blacklist = hostBlacklist.getOrPut(it) { ConcurrentHashMap() }
            blacklist[strat] = System.currentTimeMillis() + 600000 // 10 min
            
            if (hostBlacklist.size > 1000) {
                val oldest = hostBlacklist.entries.minByOrNull { it.value.values.maxOrNull() ?: 0L }
                if (oldest != null) hostBlacklist.remove(oldest.key)
            }
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
        prefs.edit { clear() }
        HostCategory.entries.forEach { cat ->
            BypassStrategy.entries.forEach { strategyScores[cat]?.get(it)?.set(100) }
        }
    }

    fun getSessionConfig(host: String, strategy: BypassStrategy, rtt: Long): SessionConfig {
        val rnd = ThreadLocalRandom.current()
        val cat = HostClassifier.classify(host)
        val intensity = ProxyStats.censorshipIntensity.value
        
        // Adaptive configuration with jitter to avoid fingerprints
        var f1 = (frag1 + rnd.nextInt(0, 3)).coerceAtLeast(1)
        var f2 = (frag2 + rnd.nextInt(0, 5)).coerceAtLeast(1)
        var f3 = (frag3 + rnd.nextInt(0, 10)).coerceAtLeast(1)
        var d1 = (delay1 + rnd.nextLong(0, 15)).coerceAtLeast(5)
        
        // Adjust based on censorship intensity
        if (intensity > 70) {
            f1 = (f1 / 2).coerceAtLeast(1)
            d1 = (d1 * 1.5).toLong()
        }
        
        if (rtt > 250) {
            d1 = (d1 * 1.3).toLong()
        }
        
        when (cat) {
            HostCategory.STREAMING -> {
                f1 = (f1 * 3).coerceAtMost(120)
                f2 = (f2 * 2).coerceAtMost(200)
            }
            HostCategory.MESSENGER -> {
                d1 = (d1 * 0.7).toLong().coerceAtLeast(5)
            }
            HostCategory.AD -> {
                // For ads, use a very heavy/slow strategy or just return a "cheap" one if we don't want to block
                // Actually, let's make it easy to block ads by returning a strategy that we can handle specifically
                f1 = 1
                d1 = 200
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
        val bypassList = listOf(
            ".ru", ".by", ".kz", ".ua", ".su", ".local", ".lan", ".arpa",
            "yandex", "vk.com", "ok.ru", "mail.ru", "gosuslugi.ru",
            "ozon.ru", "wildberries.ru", "avito.ru", "tbank.ru", "sberbank.ru",
            "kinopoisk.ru", "rambler.ru", "mts.ru", "megafon.ru", "beeline.ru",
            "doubleclick.net", "googleadservices.com", "googletagmanager.com"
        )
        return bypassList.any { h.contains(it) }
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
                        RecoveryManager.handleEvent(RecoveryEvent.TUNNEL_STALL, "MTU Tuned")
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

    private suspend fun writeWithFake(socket: Socket, output: OutputStream, fake: ByteArray, real: ByteArray, length: Int, config: SessionConfig) {
        TtlHelper.setTtl(socket, config.fakeTtl)
        output.write(fake)
        output.flush()
        delay(config.delay1)
        TtlHelper.setTtl(socket, 64)
        output.write(real, 0, length)
        output.flush()
    }

    private suspend fun writeUdpWithFake(socket: DatagramSocket, targetAddr: InetAddress, targetPort: Int, fake: ByteArray, real: DatagramPacket, config: SessionConfig) {
        val isIpv6 = targetAddr is Inet6Address
        TtlHelper.setUdpTtl(socket, config.fakeTtl, isIpv6)
        socket.send(DatagramPacket(fake, fake.size, targetAddr, targetPort))
        delay(config.delay1)
        TtlHelper.setUdpTtl(socket, 64, isIpv6)
        socket.send(real)
    }

    suspend fun applyUdpBypass(socket: DatagramSocket, packet: DatagramPacket, config: SessionConfig, host: String) {
        val rnd = ThreadLocalRandom.current()
        val strategy = config.strategy
        val targetAddr = packet.address
        val targetPort = packet.port
        val data = packet.data
        val offset = packet.offset
        val length = packet.length

        when (strategy) {
            BypassStrategy.UDP_FAKE_DTLS -> {
                val dtls = FakePacketHelper.getCachedDtls()
                writeUdpWithFake(socket, targetAddr, targetPort, dtls, packet, config)
            }
            BypassStrategy.UDP_STUN_FAKE -> {
                val stun = FakePacketHelper.getCachedStun()
                writeUdpWithFake(socket, targetAddr, targetPort, stun, packet, config)
            }
            BypassStrategy.QUIC_INITIAL_FAKE -> {
                val initial = FakePacketHelper.getCachedQuicInitial()
                writeUdpWithFake(socket, targetAddr, targetPort, initial, packet, config)
            }
            BypassStrategy.UDP_WIREGUARD_FAKE -> {
                val wg = FakePacketHelper.getCachedWg()
                writeUdpWithFake(socket, targetAddr, targetPort, wg, packet, config)
            }
            BypassStrategy.UDP_IKE_FAKE -> {
                val ike = FakePacketHelper.getCachedIke()
                writeUdpWithFake(socket, targetAddr, targetPort, ike, packet, config)
            }
            BypassStrategy.UDP_DHCP_FAKE -> {
                val dhcp = FakePacketHelper.getCachedDhcp()
                writeUdpWithFake(socket, targetAddr, targetPort, dhcp, packet, config)
            }
            BypassStrategy.UDP_TELEGRAM_FAKE -> {
                val tg = FakePacketHelper.buildTelegramFake()
                writeUdpWithFake(socket, targetAddr, targetPort, tg, packet, config)
            }
            BypassStrategy.UDP_DISCORD_FAKE -> {
                val dc = FakePacketHelper.buildDiscordFake()
                writeUdpWithFake(socket, targetAddr, targetPort, dc, packet, config)
            }
            BypassStrategy.UDP_HIGH_VOL_PACING -> {
                val intensity = ProxyStats.censorshipIntensity.value
                if (intensity > 30) {
                    delay(rnd.nextLong(1, (intensity / 10).toLong().coerceAtLeast(2)))
                }
                socket.send(packet)
            }
            BypassStrategy.UDP_NOISE_PAD -> {
                val noise = FakePacketHelper.buildUdpNoise(rnd.nextInt(50, 200))
                writeUdpWithFake(socket, targetAddr, targetPort, noise, packet, config)
            }
            BypassStrategy.UDP_GHOST_SKEW -> {
                repeat(rnd.nextInt(1, 3)) {
                    val ghost = FakePacketHelper.buildFakeUdpPacket(rnd.nextInt(10, 40))
                    TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5), targetAddr is Inet6Address)
                    socket.send(DatagramPacket(ghost, ghost.size, targetAddr, targetPort))
                    delay(rnd.nextLong(2, 5))
                }
                TtlHelper.setUdpTtl(socket, 64, targetAddr is Inet6Address)
                socket.send(packet)
            }
            BypassStrategy.UDP_FRAGMENT_SKEW -> {
                if (length > 20) {
                    val split = length / 2
                    val p1 = data.copyOfRange(offset, offset + split)
                    TtlHelper.setUdpTtl(socket, config.fakeTtl, targetAddr is Inet6Address)
                    socket.send(DatagramPacket(p1, p1.size, targetAddr, targetPort))
                    delay(config.delay1)
                }
                TtlHelper.setUdpTtl(socket, 64, targetAddr is Inet6Address)
                socket.send(packet)
            }
            BypassStrategy.UDP_STUTTER -> {
                delay(rnd.nextLong(5, 30))
                socket.send(packet)
            }
            BypassStrategy.DNS_NOISE -> {
                if (targetPort == 53) {
                    val noise = FakePacketHelper.buildFakeUdpPacket(rnd.nextInt(40, 80))
                    writeUdpWithFake(socket, targetAddr, targetPort, noise, packet, config)
                } else {
                    socket.send(packet)
                }
            }
            else -> {
                socket.send(packet)
            }
        }
    }

    private fun isProbableHttp(data: ByteArray, length: Int): Boolean {
        if (length < 10) return false
        val c = data[0]
        return c == 'G'.code.toByte() || c == 'P'.code.toByte() || c == 'H'.code.toByte() || 
               c == 'O'.code.toByte() || c == 'C'.code.toByte() || c == 'D'.code.toByte() || c == 'T'.code.toByte()
    }

    private fun findHeaderEnd(data: ByteArray, length: Int): Int {
        for (i in 0..length - 4) {
            if (data[i] == '\r'.code.toByte() && data[i+1] == '\n'.code.toByte() &&
                data[i+2] == '\r'.code.toByte() && data[i+3] == '\n'.code.toByte()) {
                return i + 4
            }
        }
        return -1
    }

    private fun containsHostHeader(data: ByteArray, length: Int): Boolean {
        if (!isProbableHttp(data, length)) return false
        for (i in 0..length - 5) {
            if ((data[i] == 'H'.code.toByte() || data[i] == 'h'.code.toByte()) &&
                (data[i+1] == 'o'.code.toByte() || data[i+1] == 'O'.code.toByte()) &&
                (data[i+2] == 's'.code.toByte() || data[i+2] == 'S'.code.toByte()) &&
                (data[i+3] == 't'.code.toByte() || data[i+3] == 'T'.code.toByte()) &&
                data[i+4] == ':'.code.toByte()
            ) {
                return true
            }
        }
        return false
    }

    private fun injectHeaderAfterFirstLine(data: ByteArray, length: Int, header: ByteArray, output: java.io.OutputStream) {
        var firstCrLf = -1
        for (i in 0..length - 2) {
            if (data[i] == '\r'.code.toByte() && data[i+1] == '\n'.code.toByte()) {
                firstCrLf = i
                break
            }
        }
        if (firstCrLf != -1) {
            output.write(data, 0, firstCrLf + 2)
            output.write(header)
            output.write(data, firstCrLf + 2, length - (firstCrLf + 2))
        } else {
            output.write(data, 0, length)
        }
        output.flush()
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
                writeWithFake(socket, output, fake, data, length, config)
            }
            BypassStrategy.TLS_CHROME_HELLO_FAKE -> {
                val fake = FakePacketHelper.buildChromeHello(host)
                writeWithFake(socket, output, fake, data, length, config)
            }
            BypassStrategy.TLS_FIREFOX_HELLO_FAKE -> {
                val fake = FakePacketHelper.buildFirefoxHello(host)
                writeWithFake(socket, output, fake, data, length, config)
            }
            BypassStrategy.TLS_13_HELLO_FAKE -> {
                val fake = FakePacketHelper.buildTls13Hello(host)
                writeWithFake(socket, output, fake, data, length, config)
            }
            BypassStrategy.TCP_WINDOW_CLAMPING -> {
                val intensity = ProxyStats.censorshipIntensity.value
                val winSize = if (intensity > 85) rnd.nextInt(256, 512) else if (intensity > 60) rnd.nextInt(1024, 2048) else 4096
                try {
                    socket.receiveBufferSize = winSize
                    socket.sendBufferSize = winSize
                } catch (e: Exception) {}
                output.write(data, 0, length)
                output.flush()
            }
            BypassStrategy.TLS_GREASE -> {
                if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                    val greased = FakePacketHelper.addTlsGreaseExtensions(data, length)
                    output.write(greased); output.flush()
                } else if (length > 0 && data[0] == 0x16.toByte()) {
                    val fakeClientHello = FakePacketHelper.buildFakeClientHello(host, rnd.nextInt(40, 90))
                    writeWithFake(socket, output, fakeClientHello, data, length, config)
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_OOB_DESYNC -> {
                try { socket.sendUrgentData(0xFF) } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.FRAGMENT_MULTI -> {
                var pos = 0
                var isFirstPart = true
                while (pos < length) {
                    val baseSize = if (isFirstPart && pos < 500) config.frag3 else 1024
                    val size = (baseSize + rnd.nextInt(-1, 2)).coerceIn(1, 4096).coerceAtMost(length - pos)
                    output.write(data, pos, size)
                    output.flush()
                    pos += size
                    if (isFirstPart && pos > 500) isFirstPart = false
                    if (isFirstPart && pos < length) delay(rnd.nextLong(1, 5))
                }
            }
            BypassStrategy.TLS_DIRTY -> {
                if (length > 5 && data[0] == 0x16.toByte()) {
                    val dirty = data.copyOf()
                    if (length > 10) dirty[9] = (dirty[9].toInt() xor 0xFF).toByte()
                    writeWithFake(socket, output, dirty, data, length, config)
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_PAD -> {
                output.write(data, 0, length); output.flush()
                val pad = ByteArray(rnd.nextInt(100, 500)) { 0 }
                output.write(pad); output.flush()
            }
            BypassStrategy.SLOW_SEND -> {
                var pos = 0
                val limit = 500.coerceAtMost(length)
                while (pos < limit) {
                    val size = rnd.nextInt(1, 5).coerceAtMost(limit - pos)
                    output.write(data, pos, size)
                    output.flush()
                    pos += size
                    delay(config.delay1)
                }
                if (length > limit) {
                    output.write(data, limit, length - limit)
                    output.flush()
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
                if (!containsHostHeader(data, length)) {
                    output.write(data, 0, length); output.flush()
                } else {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val s = String(data, 0, headerEnd)
                        val modified = s.replace("Host:", "Host:  ", ignoreCase = true)
                        output.write(modified.toByteArray())
                        output.write(data, headerEnd, length - headerEnd)
                        output.flush()
                    } else {
                        output.write(data, 0, length); output.flush()
                    }
                }
            }
            BypassStrategy.HTTP_VERSION_SKEW -> {
                var found = false
                var idx = -1
                for (i in 0..length - 8) {
                    if (data[i] == 'H'.code.toByte() && data[i+1] == 'T'.code.toByte() && 
                        data[i+2] == 'T'.code.toByte() && data[i+3] == 'P'.code.toByte() && 
                        data[i+4] == '/'.code.toByte() && data[i+5] == '1'.code.toByte() && 
                        data[i+6] == '.'.code.toByte() && data[i+7] == '1'.code.toByte()) {
                        found = true
                        idx = i
                        break
                    }
                }
                
                if (found && idx != -1) {
                    output.write(data, 0, idx + 7)
                    output.write('2'.code) // change to HTTP/1.2
                    output.write(data, idx + 8, length - (idx + 8))
                    output.flush()
                } else {
                    output.write(data, 0, length)
                    output.flush()
                }
            }
            BypassStrategy.TCP_MSS_CLAMP -> {
                val intensity = ProxyStats.censorshipIntensity.value
                val clampSize = if (intensity > 80) 128 else if (intensity > 50) 384 else 536
                var offset = 0
                while (offset < length) {
                    val chunk = minOf(clampSize, length - offset)
                    output.write(data, offset, chunk)
                    output.flush()
                    offset += chunk
                    if (offset < length) delay(rnd.nextLong(2, 10))
                }
            }
            BypassStrategy.TCP_RST_FAKE -> {
                // For ads or blocked sites, we "reset" the connection from our side
                throw IOException("Blocked by PinkProxy strategy")
            }
            BypassStrategy.TCP_KEEP_ALIVE_FAKE -> {
                output.write(data, 0, length)
                output.flush()
                // Send a tiny empty TCP segment (simulated via empty write if possible, 
                // but usually requires raw sockets. We'll send a single space if it's likely text)
                if (rnd.nextBoolean()) {
                    output.write(' '.code)
                    output.flush()
                }
            }
            BypassStrategy.TCP_TOS_MANGLE -> {
                // We can't easily set TOS per packet in standard Java Sockets easily 
                // without reflection on Linux, but we can set it for the socket once.
                try {
                    socket.trafficClass = 0x04 // Low Delay
                } catch (e: Exception) {}
                output.write(data, 0, length)
                output.flush()
            }
            BypassStrategy.TCP_SMALL_CHUNKS -> {
                var pos = 0
                while (pos < length) {
                    val size = rnd.nextInt(1, 4).coerceAtMost(length - pos)
                    output.write(data, pos, size)
                    output.flush()
                    pos += size
                    if (pos < length) delay(rnd.nextLong(1, 5))
                }
            }
            BypassStrategy.HTTP_AUTH_RANDOM -> {
                if (!isProbableHttp(data, length)) {
                    output.write(data, 0, length); output.flush()
                } else {
                    injectHeaderAfterFirstLine(data, length, FAKE_AUTH_HEADER, output)
                }
            }
            BypassStrategy.HTTP_HEADER_FUZZING -> {
                if (!isProbableHttp(data, length)) {
                    output.write(data, 0, length); output.flush()
                } else {
                    val junkHeader = "X-Fuzz-Value: ${java.util.UUID.randomUUID()}\r\n".toByteArray()
                    injectHeaderAfterFirstLine(data, length, junkHeader, output)
                }
            }
            BypassStrategy.HTTP_METHOD_FAKE -> {
                if (length > 5) {
                    if (data[0] == 'G'.code.toByte() && data[1] == 'E'.code.toByte() && data[2] == 'T'.code.toByte()) {
                        data[0] = 'g'.code.toByte()
                        data[1] = 'E'.code.toByte()
                        data[2] = 't'.code.toByte()
                    } else if (data[0] == 'P'.code.toByte() && data[1] == 'O'.code.toByte() && data[2] == 'S'.code.toByte() && data[3] == 'T'.code.toByte()) {
                        data[0] = 'p'.code.toByte()
                        data[1] = 'O'.code.toByte()
                        data[2] = 's'.code.toByte()
                        data[3] = 'T'.code.toByte()
                    } else if (data[0] == 'H'.code.toByte() && data[1] == 'E'.code.toByte() && data[2] == 'A'.code.toByte() && data[3] == 'D'.code.toByte()) {
                        data[0] = 'h'.code.toByte()
                        data[1] = 'E'.code.toByte()
                        data[2] = 'a'.code.toByte()
                        data[3] = 'D'.code.toByte()
                    }
                }
                output.write(data, 0, length)
                output.flush()
            }
            BypassStrategy.HTTP_USER_AGENT_SKEW -> {
                if (!isProbableHttp(data, length)) {
                    output.write(data, 0, length); output.flush()
                } else {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val s = String(data, 0, headerEnd)
                        if (s.contains("User-Agent:", ignoreCase = true)) {
                            val modified = s.replace(USER_AGENT_REGEX, "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n")
                            output.write(modified.toByteArray())
                            output.write(data, headerEnd, length - headerEnd)
                            output.flush()
                        } else {
                            output.write(data, 0, length); output.flush()
                        }
                    } else {
                        output.write(data, 0, length); output.flush()
                    }
                }
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
                if (!isProbableHttp(data, length)) {
                    output.write(data, 0, length); output.flush()
                } else {
                    injectHeaderAfterFirstLine(data, length, FAKE_RANGE_HEADER, output)
                }
            }
            BypassStrategy.TLS_REHANDSHAKE_FAKE -> {
                output.write(data, 0, length); output.flush(); delay(config.delay1)
                output.write(TLS_HELLO_REQ); output.flush()
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
            BypassStrategy.TCP_URG_SKEW -> {
                try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TCP_URGENT_RANDOM -> {
                repeat(rnd.nextInt(1, 4)) {
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Exception) {}
                    delay(rnd.nextLong(5, 15))
                }
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_SNI_SKEW -> {
                if (length > 0 && data[0] == 0x16.toByte()) {
                    val fakeClientHello = FakePacketHelper.buildFakeClientHello(host, rnd.nextInt(50, 100), noMangle = false)
                    writeWithFake(socket, output, fakeClientHello, data, length, config)
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
            BypassStrategy.TCP_TIMESTAMP_MANGLE -> {
                try { socket.sendUrgentData(rnd.nextInt(1, 255)) } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                val split = (length / 3).coerceIn(1, length - 1)
                output.write(data, 0, split); output.flush(); delay(config.delay1)
                output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.PROTOCOL_CONFUSION_HTTP -> {
                // Wrap first packet in a fake HTTP CONNECT or GET
                if (length > 0 && data[0] == 0x16.toByte()) { // TLS
                    val fakeHttp = "GET / HTTP/1.1\r\nHost: $host\r\nConnection: keep-alive\r\nUpgrade: websocket\r\n\r\n".toByteArray()
                    output.write(fakeHttp); output.flush(); delay(config.delay1)
                    output.write(data, 0, length); output.flush()
                } else {
                    output.write(data, 0, length); output.flush()
                }
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
                output.write(data, 0, p1); output.flush(); delay(rnd.nextLong(20, 50))
                output.write(data, p1, p2 - p1); output.flush(); delay(rnd.nextLong(20, 50))
                output.write(data, p2, length - p2); output.flush()
            }
            BypassStrategy.TLS_LEGACY_HELLOS -> {
                val hello = FakePacketHelper.buildFakeClientHello(host, 60)
                if (hello.size > 10) { hello[1] = 0x03; hello[2] = 0x01; hello[9] = 0x03; hello[10] = 0x01 }
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(hello); output.flush()
                delay(config.delay1); TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TCP_KEEP_ALIVE_FAKE -> {
                output.write(data, 0, length); output.flush()
                repeat(3) { delay(30); try { socket.sendUrgentData(0x00) } catch (e: Exception) {} }
            }
            BypassStrategy.HTTP_HOST_CASE_MANGLE -> {
                if (!containsHostHeader(data, length)) {
                    output.write(data, 0, length); output.flush()
                } else {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val s = String(data, 0, headerEnd)
                        val mod = s.replace("Host: ", "hOsT: ")
                            .replace("host: ", "Host: ")
                            .replace("Connection: ", "connecTION: ")
                        output.write(mod.toByteArray())
                        output.write(data, headerEnd, length - headerEnd)
                        output.flush()
                    } else {
                        output.write(data, 0, length); output.flush()
                    }
                }
            }
            BypassStrategy.TLS_SESSION_TICKET_SKEW -> {
                val hello = FakePacketHelper.buildFakeClientHello(host, rnd.nextInt(100, 200))
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(hello); output.flush(); delay(config.delay1)
                output.write(TLS_SESSION_TICKET); output.flush()
                delay(config.delay2); TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_MULTI_SNI -> {
                val hello = FakePacketHelper.buildMultiSniHello(host)
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(hello); output.flush(); delay(config.delay1)
                TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.HTTP2_PREAMBLE_FAKE -> {
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(HTTP2_PREAMBLE); output.flush(); delay(10)
                TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.HTTP_CHUNKED_FAKE -> {
                // Optimization: Search for "HTTP/1.1\r\n" without allocating a String
                var foundHttp = -1
                for (i in 0..length - HTTP_1_1_CRLF.size) {
                    var match = true
                    for (j in HTTP_1_1_CRLF.indices) {
                        if (data[i + j] != HTTP_1_1_CRLF[j]) { match = false; break }
                    }
                    if (match) { foundHttp = i; break }
                }
                
                if (foundHttp != -1) {
                    val originalHeaderEnd = findHeaderEnd(data, length)
                    if (originalHeaderEnd != -1) {
                        val s = String(data, 0, originalHeaderEnd)
                        val mod = s.replace("HTTP/1.1\r\n", "HTTP/1.1\r\nTransfer-Encoding: chunked\r\n")
                        val body = data.copyOfRange(originalHeaderEnd, length)
                        output.write(mod.toByteArray()); output.flush()
                        
                        var pos = 0
                        var isFirstChunks = true
                        while (pos < body.size) {
                            val maxChunk = if (isFirstChunks && pos < 1000) 10 else 1024
                            val minChunk = if (isFirstChunks && pos < 1000) 1 else 256
                            val chunkSize = rnd.nextInt(minChunk, maxChunk + 1).coerceAtMost(body.size - pos)
                            
                            output.write(CHUNK_HEADERS[chunkSize])
                            
                            output.write(body, pos, chunkSize)
                            output.write(CRLF_BYTES)
                            output.flush()
                            
                            pos += chunkSize
                            if (isFirstChunks && pos > 1000) isFirstChunks = false
                            if (isFirstChunks) delay(rnd.nextLong(1, 4))
                        }
                        output.write(END_CHUNK_BYTES); output.flush()
                    } else {
                        output.write(data, 0, length); output.flush()
                    }
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_WINDOW_RESTRICT -> {
                socket.sendBufferSize = 512; output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_MIXED_CASE_SNI -> {
                val mixedHost = host.map { if (java.util.concurrent.ThreadLocalRandom.current().nextBoolean()) it.uppercaseChar() else it.lowercaseChar() }.joinToString("")
                val hello = FakePacketHelper.buildFakeClientHello(mixedHost, rnd.nextInt(50, 100))
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(hello); output.flush(); delay(config.delay1)
                TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_0RTT_FAKE -> {
                val hello = FakePacketHelper.buildTls13Hello(host)
                val earlyData = ByteArray(rnd.nextInt(50, 200)) { rnd.nextInt(256).toByte() }
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(hello); output.flush(); delay(5)
                output.write(earlyData); output.flush(); delay(config.delay1)
                TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_COMPRESSION_FAKE -> {
                val hello = FakePacketHelper.buildFakeClientHello(host, rnd.nextInt(50, 100))
                if (hello.size > 40) { hello[hello.size - 5] = 0x02; hello[hello.size - 4] = 0x01; hello[hello.size - 3] = 0x00 }
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(hello); output.flush(); delay(config.delay1); 
                TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_ECH_FAKE -> {
                val hello = FakePacketHelper.buildFakeClientHello(host, rnd.nextInt(40, 80))
                val ech = ByteArray(rnd.nextInt(64, 128)) { rnd.nextInt(256).toByte() }
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(hello)
                output.write(byteArrayOf(0xfe.toByte(), 0x0d.toByte(), (ech.size shr 8).toByte(), (ech.size and 0xFF).toByte()))
                output.write(ech); output.flush(); delay(config.delay1); 
                TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TCP_WINDOW_SCAN -> {
                val rnd = ThreadLocalRandom.current()
                val step = (length / (rnd.nextInt(3, 7))).coerceAtLeast(1)
                var pos = 0
                val baseWindows = listOf(256, 512, 1024, 2048, 4096, 8192)
                while (pos < length) {
                    socket.sendBufferSize = baseWindows.random()
                    val size = step.coerceAtMost(length - pos)
                    output.write(data, pos, size); output.flush()
                    pos += size
                    if (pos < length) delay(rnd.nextLong(5, 25))
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
                var hostIdx = -1
                for (i in 0..length - 5) {
                    if ((data[i] == 'H'.code.toByte() || data[i] == 'h'.code.toByte()) &&
                        (data[i+1] == 'o'.code.toByte() || data[i+1] == 'O'.code.toByte()) &&
                        (data[i+2] == 's'.code.toByte() || data[i+2] == 'S'.code.toByte()) &&
                        (data[i+3] == 't'.code.toByte() || data[i+3] == 'T'.code.toByte()) &&
                        data[i+4] == ':'.code.toByte()
                    ) {
                        hostIdx = i
                        break
                    }
                }
                
                if (hostIdx != -1) {
                    output.write(data, 0, hostIdx)
                    output.flush()
                    try { socket.sendUrgentData('X'.code) } catch (e: Exception) {}
                    delay(config.delay1)
                    output.write(data, hostIdx, length - hostIdx)
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
            BypassStrategy.TLS_CLIENT_HELLO_GREASE -> {
                if (length > 0 && data[0] == 0x16.toByte()) {
                    val grease = FakePacketHelper.buildExtension(0x0A0A, ByteArray(rnd.nextInt(1, 10)) { rnd.nextInt(256).toByte() })
                    output.write(grease); output.flush(); delay(rnd.nextLong(2, 10))
                    output.write(data, 0, length); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_CLIENT_HELLO_PAD -> {
                if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                    val padded = FakePacketHelper.injectTlsPadding(data, length, rnd.nextInt(64, 512))
                    output.write(padded); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_DATA_REPETITION -> {
                if (length > 10) {
                    val part = length.coerceAtMost(rnd.nextInt(5, 50))
                    output.write(data, 0, part); output.flush()
                    delay(rnd.nextLong(1, 5))
                    // Repeat the same part
                    output.write(data, 0, part); output.flush()
                    delay(rnd.nextLong(5, 15))
                    output.write(data, part, length - part); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_HANDSHAKE_RANDOM_PADDING -> {
                if (length > 5 && data[0] == 0x16.toByte()) {
                    val padding = FakePacketHelper.buildTlsHandshakePadding(rnd.nextInt(10, 100))
                    output.write(padding); output.flush(); delay(rnd.nextLong(2, 8))
                    output.write(data, 0, length); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_DATA_OOB_SKEW -> {
                var pos = 0
                while (pos < length) {
                    val sz = rnd.nextInt(10, 50).coerceAtMost(length - pos)
                    output.write(data, pos, sz); output.flush()
                    pos += sz
                    if (pos < length && rnd.nextInt(100) < 30) {
                        try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Exception) {}
                        delay(rnd.nextLong(1, 10))
                    }
                }
            }
            BypassStrategy.TCP_SACK_FAKE -> {
                if (length > 20) {
                    val part = length / 2
                    output.write(data, 0, part); output.flush()
                    // Simulate SACK by sending a tiny piece with urgent data
                    try { socket.sendUrgentData(0) } catch (e: Exception) {}
                    delay(rnd.nextLong(5, 15))
                    output.write(data, part, length - part); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_HOST_REORDER -> {
                if (!containsHostHeader(data, length)) {
                    output.write(data, 0, length); output.flush()
                } else {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val s = String(data, 0, headerEnd)
                        if (s.contains("Host:", ignoreCase = true)) {
                            val lines = s.split("\r\n").toMutableList()
                            val hostIdx = lines.indexOfFirst { it.startsWith("Host:", ignoreCase = true) }
                            if (hostIdx != -1 && hostIdx < lines.size - 2) {
                                val hostLine = lines.removeAt(hostIdx)
                                lines.add(1, hostLine) // Move host to 2nd line
                                output.write(lines.joinToString("\r\n").toByteArray())
                                output.write(data, headerEnd, length - headerEnd)
                                output.flush()
                            } else {
                                output.write(data, 0, length); output.flush()
                            }
                        } else {
                            output.write(data, 0, length); output.flush()
                        }
                    } else {
                        output.write(data, 0, length); output.flush()
                    }
                }
            }
            BypassStrategy.TCP_WINDOW_SIZE_SKEW -> {
                val win = intArrayOf(4096, 8192, 16384, 32768, 65535).random()
                socket.receiveBufferSize = win
                socket.sendBufferSize = win
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_CLIENT_HELLO_REORDER -> {
                if (length > 10 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                    // Split ClientHello into multiple records
                    val header = data.copyOfRange(0, 5)
                    val body = data.copyOfRange(5, length)
                    val part1 = body.size / 3
                    val part2 = body.size * 2 / 3
                    
                    // Record 1
                    output.write(data[0].toInt()); output.write(data[1].toInt()); output.write(data[2].toInt())
                    output.write((part1 shr 8) and 0xff)
                    output.write(part1 and 0xff)
                    output.write(body, 0, part1); output.flush()
                    delay(rnd.nextLong(5, 15))
                    
                    // Record 2
                    output.write(data[0].toInt()); output.write(data[1].toInt()); output.write(data[2].toInt())
                    val len2 = part2 - part1
                    output.write((len2 shr 8) and 0xff)
                    output.write(len2 and 0xff)
                    output.write(body, part1, len2); output.flush()
                    delay(rnd.nextLong(5, 15))
                    
                    // Record 3
                    output.write(data[0].toInt()); output.write(data[1].toInt()); output.write(data[2].toInt())
                    val len3 = body.size - part2
                    output.write((len3 shr 8) and 0xff)
                    output.write(len3 and 0xff)
                    output.write(body, part2, len3); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_SNI_SPLIT -> {
                if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                    val sniOffset = TlsParser.findSniOffset(data, length)
                    if (sniOffset != -1 && sniOffset > 5) {
                        // Split right before the SNI string starts (usually 3 bytes before for type/length)
                        val splitPos = (sniOffset - 3).coerceAtLeast(5)
                        output.write(data, 0, splitPos); output.flush()
                        delay(rnd.nextLong(2, 10))
                        output.write(data, splitPos, length - splitPos); output.flush()
                    } else {
                        val part = length / 2
                        output.write(data, 0, part); output.flush()
                        delay(rnd.nextLong(2, 10))
                        output.write(data, part, length - part); output.flush()
                    }
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_CLIENT_HELLO_CHOP -> {
                if (length > 5 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                    // Chop the first 50 bytes into tiny pieces
                    val limit = 50.coerceAtMost(length)
                    for (i in 0 until limit) {
                        output.write(data[i].toInt())
                        output.flush()
                        if (i < 10) delay(rnd.nextLong(1, 3))
                    }
                    if (length > limit) {
                        output.write(data, limit, length - limit)
                        output.flush()
                    }
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_APP_DATA_SPLIT -> {
                if (length > 5 && data[0] == 0x17.toByte()) {
                    // Split the first application data record
                    val head = 5
                    val bodyLen = length - head
                    if (bodyLen > 1) {
                        val part = rnd.nextInt(1, bodyLen)
                        // Record 1
                        output.write(data[0].toInt()); output.write(data[1].toInt()); output.write(data[2].toInt())
                        output.write((part shr 8) and 0xff); output.write(part and 0xff)
                        output.write(data, head, part); output.flush()
                        delay(rnd.nextLong(1, 5))
                        // Record 2
                        val part2 = bodyLen - part
                        output.write(data[0].toInt()); output.write(data[1].toInt()); output.write(data[2].toInt())
                        output.write((part2 shr 8) and 0xff); output.write(part2 and 0xff)
                        output.write(data, head + part, part2); output.flush()
                    } else { output.write(data, 0, length); output.flush() }
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_HOST_MANGLE -> {
                // Efficient byte-level replacement of "Host:" to "hOsT:"
                var modified = false
                var newData: ByteArray? = null
                for (i in 0 until length - 4) {
                    if ((data[i] == 'H'.code.toByte() || data[i] == 'h'.code.toByte()) &&
                        (data[i+1] == 'o'.code.toByte() || data[i+1] == 'O'.code.toByte()) &&
                        (data[i+2] == 's'.code.toByte() || data[i+2] == 'S'.code.toByte()) &&
                        (data[i+3] == 't'.code.toByte() || data[i+3] == 'T'.code.toByte()) &&
                        data[i+4] == ':'.code.toByte()) {
                        newData = data.copyOf(length)
                        newData[i] = 'h'.code.toByte()
                        newData[i+1] = 'O'.code.toByte()
                        newData[i+2] = 's'.code.toByte()
                        newData[i+3] = 'T'.code.toByte()
                        modified = true
                        break
                    }
                }
                output.write(if (modified) newData!! else data, 0, length)
                output.flush()
            }
            BypassStrategy.HTTP_FRAGMENT -> {
                if (length > 20) {
                    val part = rnd.nextInt(5, 15)
                    output.write(data, 0, part); output.flush()
                    delay(rnd.nextLong(2, 8))
                    output.write(data, part, length - part); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_HOST_SMUGGLE -> {
                if (!containsHostHeader(data, length)) {
                    output.write(data, 0, length); output.flush()
                } else {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val s = String(data, 0, headerEnd, Charsets.US_ASCII)
                        if (s.contains("Host:", ignoreCase = true)) {
                            val lines = s.split("\r\n").toMutableList()
                            val hostIdx = lines.indexOfFirst { it.startsWith("Host:", ignoreCase = true) }
                            if (hostIdx != -1) {
                                lines.add(hostIdx, "Host: www.google.com")
                                val smuggled = lines.joinToString("\r\n")
                                output.write(smuggled.toByteArray(Charsets.US_ASCII))
                                output.write(data, headerEnd, length - headerEnd)
                                output.flush()
                            } else {
                                output.write(data, 0, length); output.flush()
                            }
                        } else {
                            output.write(data, 0, length); output.flush()
                        }
                    } else {
                        output.write(data, 0, length); output.flush()
                    }
                }
            }
            BypassStrategy.TCP_SACK_PANIC -> {
                // Force strange window sizes to confuse DPI state tracking
                socket.receiveBufferSize = 1
                socket.sendBufferSize = 1460
                output.write(data, 0, length); output.flush()
                delay(rnd.nextLong(1, 3))
                socket.receiveBufferSize = 65535
            }
            BypassStrategy.TCP_GHOST_SKEW -> {
                // Send fake data with low TTL to poison DPI state
                val ghost = FakePacketHelper.buildFakeUdpPacket(rnd.nextInt(10, 60))
                TtlHelper.setTtl(socket, rnd.nextInt(3, 7))
                output.write(ghost); output.flush()
                delay(rnd.nextLong(2, 10))
                TtlHelper.setTtl(socket, 64)
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_CLIENT_HELLO_SHUFFLE -> {
                if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                    val shuffled = FakePacketHelper.shuffleTlsExtensions(data, length)
                    output.write(shuffled); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.UDP_NOISE_PAD -> {
                // Handled in UdpTransportHandler mostly, but here for completeness if used over TCP (not recommended)
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_RECORD_PADDING -> {
                output.write(data, 0, length)
                if (length > 0 && data[0] == 0x17.toByte()) { // Application Data
                    val padSize = rnd.nextInt(1, 100)
                    val padRecord = ByteArray(5 + padSize)
                    padRecord[0] = 0x17.toByte() // Type
                    padRecord[1] = 0x03.toByte(); padRecord[2] = 0x03.toByte() // Version
                    padRecord[3] = (padSize shr 8).toByte(); padRecord[4] = (padSize and 0xFF).toByte()
                    rnd.nextBytes(padRecord.copyOfRange(5, 5 + padSize))
                    output.write(padRecord)
                }
                output.flush()
            }
            BypassStrategy.TLS_RECORD_FRAGMENTATION -> {
                if (length > 5 && (data[0] == 0x16.toByte() || data[0] == 0x17.toByte())) {
                    val head = 5
                    val bodyLen = length - head
                    if (bodyLen > 100) {
                        val chunkSize = rnd.nextInt(20, 50)
                        var sent = 0
                        while (sent < bodyLen) {
                            val cur = (bodyLen - sent).coerceAtMost(chunkSize)
                            output.write(data[0].toInt()); output.write(data[1].toInt()); output.write(data[2].toInt())
                            output.write((cur shr 8) and 0xff); output.write(cur and 0xff)
                            output.write(data, head + sent, cur); output.flush()
                            sent += cur
                            if (sent < bodyLen) delay(rnd.nextLong(1, 3))
                        }
                    } else { output.write(data, 0, length); output.flush() }
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
            BypassStrategy.TLS_GREASE_SKEW -> {
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(GREASE_BYTES); output.flush()
                delay(config.delay1); TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.ADAPTIVE_CHUNK -> {
                val rnd = ThreadLocalRandom.current()
                val jitter = ProxyStats.jitter.value.coerceIn(1, 100)
                val rtt = _currentRttMs.value.coerceIn(20, 500)
                
                // Base chunk size inversely proportional to censorship level and jitter
                val currentIntensity = ProxyStats.censorshipIntensity.value
                val baseChunk = if (currentIntensity > 60 || jitter > 40) 1 else 3
                var offset = 0
                while (offset < length) {
                    val chunkSize = rnd.nextInt(baseChunk, baseChunk + 4).coerceAtMost(length - offset)
                    output.write(data, offset, chunkSize)
                    output.flush()
                    
                    // Delay proportional to RTT and jitter to simulate unstable network
                    val baseDelay = (rtt / 40).coerceAtLeast(2)
                    val d = (baseDelay + rnd.nextLong(0, 10) + jitter / 15).coerceIn(2, 60)
                    delay(d)
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
                val probe = ProxyStats.obtain8k()
                try {
                    java.util.Arrays.fill(probe, 0.toByte())
                    repeat(3) { 
                        delay(rnd.nextLong(5, 15))
                        output.write(probe, 0, 1200)
                        output.flush() 
                    }
                } finally {
                    ProxyStats.release8k(probe)
                }
            }
            BypassStrategy.PROTOCOL_CONFUSION_SSH -> {
                val fake = FakePacketHelper.buildSshHandshake()
                writeWithFake(socket, output, fake, data, length, config)
            }
            BypassStrategy.PROTOCOL_CONFUSION_BITTORRENT -> {
                val fake = FakePacketHelper.buildBitTorrentHandshake()
                writeWithFake(socket, output, fake, data, length, config)
            }
            BypassStrategy.PROTOCOL_CONFUSION_HTTP -> {
                val fake = FakePacketHelper.buildHttpHandshake()
                writeWithFake(socket, output, fake, data, length, config)
            }
            BypassStrategy.TCP_SMALL_CHUNKS -> {
                var offset = 0
                while (offset < length) {
                    val size = rnd.nextInt(1, 15)
                    val chunk = minOf(size, length - offset)
                    output.write(data, offset, chunk)
                    output.flush()
                    offset += chunk
                    if (offset < length) delay(rnd.nextLong(1, 4))
                }
            }
            BypassStrategy.TCP_ACK_DELAY -> {
                delay(rnd.nextLong(150, 400))
                output.write(data, 0, length)
                output.flush()
            }
            BypassStrategy.TCP_RANDOM_PADDING -> {
                output.write(data, 0, length)
                val padSize = rnd.nextInt(1, 100)
                val pad = ByteArray(padSize)
                rnd.nextBytes(pad)
                output.write(pad)
                output.flush()
            }
            BypassStrategy.WINDOW_SIZE -> {
                try {
                    socket.receiveBufferSize = rnd.nextInt(1024, 4096)
                    socket.sendBufferSize = rnd.nextInt(1024, 4096)
                } catch (e: Exception) {}
                output.write(data, 0, length); output.flush()
            }

            BypassStrategy.TCP_TOS_MANGLE -> {
                try { socket.trafficClass = 0x08 } catch (e: Exception) {}
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.WS_HANDSHAKE_FAKE -> {
                val ws = FakePacketHelper.buildFakeWebSocketHandshake(host)
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(ws); output.flush()
                delay(config.delay1); TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.SSH_HANDSHAKE_FAKE -> {
                val ssh = FakePacketHelper.buildFakeSshHandshake()
                output.write(ssh); output.flush(); delay(config.delay1)
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.UDP_DTLS_FAKE -> {
                val dtls = byteArrayOf(0x16, 0xfe.toByte(), 0xff.toByte()) + ByteArray(20) { rnd.nextInt(256).toByte() }
                output.write(dtls); output.flush(); delay(config.delay1)
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.HTTP_KEEP_ALIVE_FAKE -> {
                val keepAlive = "OPTIONS * HTTP/1.1\r\nHost: $host\r\nConnection: keep-alive\r\n\r\n".toByteArray()
                output.write(keepAlive); output.flush(); delay(config.delay1)
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.CHAOS -> {
                val pool = BypassStrategy.entries.filter { 
                    it != BypassStrategy.CHAOS && 
                    it != BypassStrategy.DIRECT && 
                    it.family != StrategyFamily.DNS 
                }
                val s1 = pool.random()
                val s2 = pool.random()
                // Mix two strategies if length permits
                if (length > 20 && s1.family == StrategyFamily.FRAGMENTATION && s2.family == StrategyFamily.TCP) {
                     applyBypass(socket, output, data.copyOfRange(0, 5), 5, config.copy(strategy = s1), host)
                     applyBypass(socket, output, data.copyOfRange(5, length), length - 5, config.copy(strategy = s2), host)
                } else {
                     applyBypass(socket, output, data, length, config.copy(strategy = s1), host)
                }
            }
            BypassStrategy.UDP_GHOST_SKEW, BypassStrategy.UDP_FRAGMENT_SKEW, BypassStrategy.UDP_STUTTER -> {
                // These are primarily for UDP handler, but if called here we do a simple desync
                val split = length / 2
                output.write(data, 0, split); output.flush(); delay(rnd.nextLong(5, 15))
                output.write(data, split, length - split); output.flush()
            }
            else -> {
                val split = 1; output.write(data, 0, split); output.flush(); delay(5)
                output.write(data, split, length - split); output.flush()
            }
        }
    }
}

