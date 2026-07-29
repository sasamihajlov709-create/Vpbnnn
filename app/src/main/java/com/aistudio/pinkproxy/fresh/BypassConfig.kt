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
    
    private val CHAOS_POOL by lazy {
        BypassStrategy.entries.filter { 
            it != BypassStrategy.CHAOS && 
            it != BypassStrategy.DIRECT && 
            it.family != StrategyFamily.DNS 
        }
    }
    
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
    @Volatile var blockQuic = false
    @Volatile var isCharging = true
    @Volatile var preferIpv6 = false

    // Circuit Breaker state
    private val circuitBreakers = ConcurrentHashMap<BypassStrategy, Long>()
    private val BREAKER_TTL = 5 * 60 * 1000L // 5 minutes
    
    // Session Stickiness with TTL
    private val hostStrategyMemory = ConcurrentHashMap<String, Pair<BypassStrategy, Long>>()
    private val SESSION_TTL = 30 * 60 * 1000L // 30 minutes
    
    private val censorHeuristic = ConcurrentHashMap<String, Int>()
    private val hostLockTime = ConcurrentHashMap<String, Long>()

    fun isHostProbablyCensored(host: String): Boolean {
        if (hostLockTime[host]?.let { System.currentTimeMillis() - it < 300_000 } == true) return true
        return (censorHeuristic[host] ?: 0) >= 3
    }

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
            circuitBreakers.clear()
        }
    }

    private val lastCleanup = AtomicLong(0)
    private fun ensureMemoryEfficiency() {
        val now = System.currentTimeMillis()
        if (now - lastCleanup.get() < 60000L) return
        lastCleanup.set(now)
        
        // Limit session memory size to prevent leaks
        if (hostStrategyMemory.size > 2000) {
            val sorted = hostStrategyMemory.entries.sortedBy { it.value.second }
            val toRemove = sorted.take(500)
            toRemove.forEach { hostStrategyMemory.remove(it.key) }
        }
        
        // Clear old circuit breakers
        circuitBreakers.entries.removeIf { now - it.value > BREAKER_TTL }
        
        // Clear old blacklist entries
        hostBlacklist.forEach { (_, map) ->
            map.entries.removeIf { now - it.value > BREAKER_TTL * 2 }
        }
        hostBlacklist.entries.removeIf { it.value.isEmpty() }
    }

    fun loadTuningSettings(context: Context) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
        isAutoTuning = prefs.getBoolean("is_auto_tuning", true)
        blockQuic = prefs.getBoolean("block_quic", false)
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
        } catch (e: Throwable) {
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
        ensureMemoryEfficiency()
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
                            if (remembered == BypassStrategy.FAKE_PACKET || remembered == BypassStrategy.TCP_OOB_DESYNC || remembered == BypassStrategy.BYEBYEDPI_SIM || remembered == BypassStrategy.BYEBYEDPI_HYBRID || remembered == BypassStrategy.TCP_DATA_DESYNC || remembered == BypassStrategy.TCP_REVERSE_FRAG) boostedScore += 65
                        }
                        DpiType.CONNECTION_TIMEOUT -> {
                            if (remembered == BypassStrategy.TLS_CLIENT_HELLO_CHOP || remembered == BypassStrategy.FRAGMENT_MULTI || remembered == BypassStrategy.BYEBYEDPI_HYBRID || remembered == BypassStrategy.TCP_REVERSE_FRAG) boostedScore += 45
                            if (remembered == BypassStrategy.TCP_ZERO_WINDOW_STALL) boostedScore += 30
                        }
                        DpiType.TLS_SNI_BLOCK -> {
                            if (remembered.family == StrategyFamily.TLS || remembered.family == StrategyFamily.FRAGMENTATION) boostedScore += 50
                            if (remembered == BypassStrategy.SNI_SPLIT || remembered == BypassStrategy.TLS_SNI_SKEW || remembered == BypassStrategy.TLS_SNI_NULL_EXT || remembered == BypassStrategy.TLS_CLIENT_HELLO_PAD_EXTREME || remembered == BypassStrategy.BYEBYEDPI_SIM || remembered == BypassStrategy.BYEBYEDPI_HYBRID) boostedScore += 70
                        }
                        DpiType.DNS_POISONING -> {
                            if (remembered == BypassStrategy.DNS_OVER_TCP || remembered == BypassStrategy.DNS_OVER_TCP_FORCE || remembered == BypassStrategy.DNS_NOISE) boostedScore += 60
                        }
                        DpiType.HTTP_BLOCK -> {
                            if (remembered.family == StrategyFamily.HTTP) boostedScore += 50
                            if (remembered == BypassStrategy.HTTP_HOST_MANGLE || remembered == BypassStrategy.HTTP_FRAGMENT || remembered == BypassStrategy.HTTP_HOST_REVERSE || remembered == BypassStrategy.HTTP_MULTI_LINE_MANGLE) boostedScore += 60
                        }
                        DpiType.TCP_RESET -> {
                            if (remembered == BypassStrategy.TCP_REORDER_DESYNC || remembered == BypassStrategy.TCP_URGENT_SKEW || remembered == BypassStrategy.OOB_DESYNC) boostedScore += 70
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

            val group = entry.key.group
            if (group == preferredGroup) weight *= 2.5
            else if (group == StrategyGroup.EXTREME && level < 30) weight *= 0.2 // Don't over-engineer simple cases

            // Category-specific weights
            when (cat) {
                HostCategory.STREAMING -> {
                    if (entry.key.family == StrategyFamily.FRAGMENTATION) weight *= 1.5
                    if (entry.key == BypassStrategy.WINDOW_SIZE_MANGLE) weight *= 2.0
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
                HostCategory.GAMING -> {
                    if (entry.key.family == StrategyFamily.UDP || entry.key == BypassStrategy.UDP_HIGH_VOL_PACING) weight *= 2.5
                    if (entry.key.cost > 3) weight *= 0.5 
                }
                HostCategory.FINANCE -> {
                    if (entry.key.group == StrategyGroup.LIGHT) weight *= 1.8 
                }
                HostCategory.GOVERNMENT, HostCategory.SECURITY -> {
                    if (entry.key.group == StrategyGroup.EXTREME) weight *= 2.0
                    if (entry.key.family == StrategyFamily.TLS) weight *= 1.5
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
                try {
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

                // MTU Auto-Probing: If we see many resets on large packets, reduce MSS/MTU
                val mssFailures = ProxyStats.mssFailureCount.value
                if (mssFailures > 5 && _currentMtu.value > 1200) {
                    _currentMtu.value = (_currentMtu.value - 20).coerceAtLeast(1100)
                    ProxyStats.logRecovery("MTU Probing: Reducing MTU to ${_currentMtu.value} due to MSS failures.")
                    ProxyStats.resetMssFailureCount()
                }
                
                // IP Version Preference: If stability is low, try flipping IPv6 preference
                val currentStability = ProxyStats.stabilityScore.value
                if (currentStability < 40 && currentRate < 40) {
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
                } catch (e: kotlinx.coroutines.CancellationException) { throw e } catch (e: Throwable) { android.util.Log.e("BypassConfig", "Optimizer error", e) }
            }
        }
    }

    fun recordSuccess(strat: BypassStrategy, rtt: Long, host: String?) {
        ProxyStats.recordGlobalSuccess(rtt)
        if (rtt > 0) {
            TrafficShaper.updateRtt(rtt)
            _currentRttMs.value = (_currentRttMs.value * 7 + rtt) / 8
        }
        
        ProxyStats.recordCensorshipEvent(false)
        
        if (host != null) {
            censorHeuristic.remove(host)
            hostLockTime.remove(host)
            
            val cat = HostClassifier.classify(host)
            val scores = strategyScores[cat] ?: strategyScores[HostCategory.OTHER]!!
            
            val bonus = when {
                rtt < 150 -> 25
                rtt < 400 -> 15
                else -> 5
            }
            scores[strat]?.addAndGet(bonus)?.let { 
                if (it > 2000) scores[strat]?.set(2000)
            }

            hostStrategyMemory[host] = strat to (System.currentTimeMillis() + SESSION_TTL)
            hostBlacklist[host]?.remove(strat)
        }
        
        strategyStats[strat]?.let { stats ->
            stats.successes.incrementAndGet()
            stats.totalRtt.addAndGet(rtt)
        }
        
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
                val cat = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
                val scores = strategyScores[cat] ?: strategyScores[HostCategory.OTHER]!!
                listOf(BypassStrategy.FAKE_PACKET, BypassStrategy.TCP_OOB_DESYNC, BypassStrategy.SNI_SPLIT, BypassStrategy.BYEBYEDPI_SIM, BypassStrategy.BYEBYEDPI_HYBRID, BypassStrategy.TCP_DATA_DESYNC, BypassStrategy.TCP_REVERSE_FRAG).forEach {
                    scores[it]?.addAndGet(30)
                }
            }
            DpiType.TLS_SNI_BLOCK -> {
                val cat = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
                val scores = strategyScores[cat] ?: strategyScores[HostCategory.OTHER]!!
                listOf(BypassStrategy.SNI_SPLIT, BypassStrategy.TLS_SNI_SKEW, BypassStrategy.TLS_SNI_NULL_EXT, BypassStrategy.BYEBYEDPI_HYBRID, BypassStrategy.TCP_REVERSE_FRAG).forEach {
                    scores[it]?.addAndGet(40)
                }
            }
            DpiType.CONNECTION_TIMEOUT -> {
                if (ProxyStats.censorshipIntensity.value > 50) {
                    _currentMtu.update { (it - 50).coerceAtLeast(1000) }
                }
            }
            DpiType.UDP_BLOCK -> {
                val cat = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
                val scores = strategyScores[cat] ?: strategyScores[HostCategory.OTHER]!!
                listOf(BypassStrategy.UDP_QUIC_SMART_SHADOW, BypassStrategy.UDP_DNS_REORDER_HYBRID, BypassStrategy.QUIC_INITIAL_FRAGMENT, BypassStrategy.UDP_IP_FRAG, BypassStrategy.UDP_SKEW_REVERSE).forEach {
                    scores[it]?.addAndGet(35)
                }
            }
            else -> {}
        }
    }

    enum class FailureReason {
        TIMEOUT,
        TCP_RESET,
        SSL_HANDSHAKE_ERROR,
        CONNECTION_REFUSED,
        UNKNOWN
    }

    fun recordFailure(strat: BypassStrategy, host: String?, reason: FailureReason = FailureReason.UNKNOWN) {
        ProxyStats.recordCensorshipEvent(true)
        
        if (host != null) {
            val count = censorHeuristic.getOrDefault(host, 0) + 1
            censorHeuristic[host] = count
            if (count >= 5) {
                hostLockTime[host] = System.currentTimeMillis()
                Log.w("PinkProxy", "Host $host is locked for 5m due to persistent failures")
            }
        }
        
        val stats = strategyStats[strat]
        stats?.failures?.incrementAndGet()

        val cat = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
        val scores = strategyScores[cat] ?: strategyScores[HostCategory.OTHER]!!
        
        // Dynamic penalty based on failure reason
        val penalty = when (reason) {
            FailureReason.TCP_RESET -> if (ProxyStats.censorshipIntensity.value > 80) -70 else -50
            FailureReason.SSL_HANDSHAKE_ERROR -> -40
            FailureReason.TIMEOUT -> -20
            else -> if (ProxyStats.censorshipIntensity.value > 80) -50 else -30
        }
        
        scores[strat]?.addAndGet(penalty)?.let {
            if (it < 5) scores[strat]?.set(5)
        }

        if (reason == FailureReason.TCP_RESET) {
            ProxyStats.recordDpiEvent(DpiType.TCP_RESET)
        }

        // Circuit Breaker: if strategy fails too much globally, disable it for a while
        if ((stats?.failures?.get() ?: 0) % 3 == 0L) {
             val successes = stats?.successes?.get() ?: 0
             val failures = stats?.failures?.get() ?: 0
             val total = (successes + failures).coerceAtLeast(1)
             val failRate = failures.toDouble() / total
             if (failRate > 0.4 && total > 10) {
                 circuitBreakers[strat] = System.currentTimeMillis()
                 ProxyStats.logRecovery("Circuit breaker triggered for $strat (fail rate: ${(failRate * 100).toInt()}%)")
             }
        }
        
        host?.let { 
             val black = hostBlacklist.computeIfAbsent(it) { ConcurrentHashMap() }
             black[strat] = System.currentTimeMillis()
             if (hostStrategyMemory[it]?.first == strat) {
                 hostStrategyMemory.remove(it)
             }
        }
    }
    fun recordFailure(strat: BypassStrategy, isCritical: Boolean, context: Context?) = recordFailure(strat, null as String?)

    fun performSelfHealing() {
        val rate = ProxyStats.getSuccessRate()
        val lockedCount = hostLockTime.filter { System.currentTimeMillis() - it.value < 300_000 }.size
        
        if ((rate < 40 || lockedCount >= 5) && !isPanicMode) {
            panicOptimize()
        } else if (rate > 85 && lockedCount == 0 && isPanicMode) {
            _isPanicModeFlow.value = false
            ProxyStats.logRecovery("Stability restored: $rate%. Normal mode.")
        }
    }

    fun panicOptimize() {
        _isPanicModeFlow.value = true
        
        val oldMtu = _currentMtu.value
        val newMtu = when {
            oldMtu > 1300 -> 1280
            oldMtu > 1200 -> 1100
            else -> 1000
        }
        _currentMtu.value = newMtu
        
        ProxyStats.logRecovery("Panic Mode Active: MTU $oldMtu -> $newMtu. Aggressive exploration started.")
        
        rotateGlobalStrategy()
        hostStrategyMemory.clear()
        censorHeuristic.clear() // Clear heuristics to try again
        
        // Boost strategy search: increase variety
        HostCategory.entries.forEach { cat ->
            strategyScores[cat]?.forEach { (_, score) ->
                if (score.get() < 80) score.set(100)
            }
        }
        
        frag1 = 1
        frag2 = ThreadLocalRandom.current().nextInt(2, 6)
        delay1 = 50
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
            HostCategory.AI -> {
                f1 = 1
                d1 = (d1 * 1.5).toLong() // More delay for AI to avoid handshake detection
            }
            HostCategory.FINANCE -> {
                f1 = (f1 * 3).coerceAtLeast(15) // Larger initial fragments for finance (speed)
                d1 = (d1 * 0.6).toLong().coerceAtLeast(3)
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

    private val recentFailuresCount = java.util.concurrent.atomic.AtomicInteger(0)
    
    fun recordStrategyResult(host: String, strategy: BypassStrategy, success: Boolean, avgDuration: Long = 50L) {
        if (success) {
            recordSuccess(strategy, avgDuration, host)
            recentFailuresCount.set((recentFailuresCount.get() - 1).coerceAtLeast(0))
        } else {
            recordFailure(strategy, host)
            if (recentFailuresCount.incrementAndGet() >= 8) {
                recentFailuresCount.set(0)
                performEmergencyRotation()
            }
        }
    }

    private fun performEmergencyRotation() {
        ProxyStats.logRecovery("CRITICAL FAILURE RATE. Performing emergency strategy rotation...")
        _isPanicModeFlow.value = true
        rotateGlobalStrategy()
        ProxyStats.updateCensorshipIntensity((ProxyStats.censorshipIntensity.value + 20).coerceAtMost(100))
    }

    @Volatile var activeVpnService: VpnService? = null
    
    private fun applyHttpSmuggling(data: ByteArray, length: Int): ByteArray {
        val s = String(data, 0, length, Charsets.US_ASCII)
        if (!s.contains("Host:", ignoreCase = true)) return data.copyOfRange(0, length)
        
        val rnd = java.util.concurrent.ThreadLocalRandom.current()
        val innocent = listOf("google.com", "bing.com", "microsoft.com", "apple.com", "cdn.cloudflare.net").random()
        
        val sb = StringBuilder()
        val lines = s.split("\r\n")
        var firstLine = true
        for (line in lines) {
            if (line.isBlank() && !firstLine) continue
            if (firstLine) {
                sb.append(line).append("\r\n")
                // Inject fake smuggling headers after request line
                if (rnd.nextBoolean()) {
                    sb.append("Transfer-Encoding: chunked\r\n")
                    sb.append("Content-Length: 0\r\n")
                }
                firstLine = false
                continue
            }
            if (line.startsWith("Host:", ignoreCase = true)) {
                // Technique 1: Duplicate Host with different case and innocent value
                sb.append("hOsT: ").append(innocent).append("\r\n")
                // Technique 1.5: Space before colon
                val parts = line.split(":", limit = 2)
                if (parts.size == 2 && rnd.nextBoolean()) {
                    sb.append(parts[0]).append(" : ").append(parts[1].trim()).append("\r\n")
                } else {
                    sb.append(line).append("\r\n")
                }
                // Technique 2: X-Forwarded-For injection
                sb.append("X-Forwarded-For: ").append(rnd.nextInt(1, 255)).append(".")
                  .append(rnd.nextInt(1, 255)).append(".")
                  .append(rnd.nextInt(1, 255)).append(".")
                  .append(rnd.nextInt(1, 255)).append("\r\n")
            } else {
                sb.append(line).append("\r\n")
            }
        }
        sb.append("\r\n")
        return sb.toString().toByteArray(Charsets.US_ASCII)
    }

    private var weatherJob: Job? = null
    fun startNetworkWeatherSensor(scope: CoroutineScope) {
        if (weatherJob?.isActive == true) return
        weatherJob = scope.launch(ProxyDispatcher.io) {
            while (isActive) {
                delay(15000)
                val successRate = ProxyStats.getSuccessRate()
                val jitter = ProxyStats.jitter.value
                val latency = _currentRttMs.value
                
                // Nuclear Automation: If success rate is low and latency is high, 
                // auto-boost censorship intensity to trigger heavier strategies.
                if (successRate < 50 && (latency > 1000 || jitter > 300)) {
                    ProxyStats.updateCensorshipIntensity((ProxyStats.censorshipIntensity.value + 15).coerceAtMost(100))
                    ProxyStats.logRecovery("Network Weather: SEVERE. Boosting censorship intensity to ${ProxyStats.censorshipIntensity.value}%")
                } else if (successRate > 95 && latency < 300) {
                    ProxyStats.updateCensorshipIntensity((ProxyStats.censorshipIntensity.value - 5).coerceAtLeast(0))
                }
            }
        }
    }

    private var learningJob: Job? = null
    fun startLearningTask(scope: CoroutineScope) {
        if (learningJob?.isActive == true) return
        learningJob = scope.launch(ProxyDispatcher.io) {
            val censoredCanaries = listOf("google.com", "telegram.org", "discord.com", "github.com")
            while (isActive) {
                delay(600000) // Every 10 minutes
                if (ProxyStats.activeConnections.value == 0) {
                    val target = censoredCanaries.random()
                    val currentBest = getBestStrategyForHost(target)
                    val candidate = BypassStrategy.entries.filter { it.group != StrategyGroup.LIGHT }.random()
                    
                    if (candidate != currentBest) {
                        ProxyStats.logRecovery("Learning: Testing $candidate on $target...")
                        val success = ServiceChecker.probeHostWithStrategy(target, candidate)
                        if (success) {
                            ProxyStats.logRecovery("Learning: $candidate works for $target! Boosting score.")
                            recordSuccess(candidate, 100, target)
                        } else {
                            recordFailure(candidate, target)
                        }
                    }
                    
                    // Also probe MTU occasionally
                    if (java.util.concurrent.ThreadLocalRandom.current().nextInt(100) < 35) {
                        val bestMtu = ServiceChecker.probeBestMtu(target)
                        if (bestMtu > 500 && bestMtu < 1500) {
                            val newMss = (bestMtu - 40).coerceAtLeast(512)
                            if (newMss < ProxyStats.maxMss.value) {
                                ProxyStats.logRecovery("Learning: Reducing Max MSS to $newMss based on probe of $target")
                                ProxyStats.updateMaxMss(newMss)
                            }
                        }
                    }
                }
            }
        }
    }
    fun stopLearningTask() {
        learningJob?.cancel()
        learningJob = null
    }

    fun isHostCensored(host: String): Boolean {
        val h = host.lowercase(java.util.Locale.ROOT)
        return h.contains("youtube") || h.contains("googlevideo") || h.contains("ytimg") || h.contains("ggpht") ||
               h.contains("facebook") || h.contains("instagram") || h.contains("twitter") || h.contains("x.com") ||
               h.contains("telegram") || h.contains("t.me") || h.contains("discord") || h.contains("fbcdn") ||
               h.contains("netflix") || h.contains("openai") || h.contains("chatgpt") || h.contains("claude") ||
               h.contains("anthropic") || h.contains("medium.com") || h.contains("quora.com") || h.contains("github") ||
               h.contains("gitlab") || h.contains("pinterest") || h.contains("spotify") || h.contains("bbc") ||
               h.contains("dw.com") || h.contains("reuters") || h.contains("nytimes") || h.contains("bloomberg") ||
               h.contains("voa") || h.contains("rferl") || h.contains("svoboda") || h.contains("meduza") ||
               h.contains("theins") || h.contains("vpost") || h.contains("novayagazeta") || h.contains("holod")
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
        val split = config.frag1.coerceIn(1, length - 1)
        output.write(real, 0, split)
        output.flush()
        delay(config.delay2)
        output.write(real, split, length - split)
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
        val data = packet.data
        val length = packet.length
        val offset = packet.offset
        val targetAddr = packet.address
        val targetPort = packet.port ?: return
        val isIpv6 = targetAddr is java.net.Inet6Address

        when (config.strategy) {
            BypassStrategy.UDP_FAKE_DTLS -> {
                val fake = byteArrayOf(0x16, 0xfe.toByte(), 0xff.toByte()) + ByteArray(rnd.nextInt(10, 30)) { rnd.nextInt(256).toByte() }
                writeUdpWithFake(socket, targetAddr, targetPort, fake, packet, config)
            }
            BypassStrategy.UDP_WIREGUARD_FAKE -> {
                val fake = byteArrayOf(0x01, 0x00, 0x00, 0x00) + ByteArray(28) { rnd.nextInt(256).toByte() }
                writeUdpWithFake(socket, targetAddr, targetPort, fake, packet, config)
            }
            BypassStrategy.UDP_STUN_FAKE -> {
                val fake = byteArrayOf(0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4.toByte(), 0x42) + ByteArray(12) { rnd.nextInt(256).toByte() }
                writeUdpWithFake(socket, targetAddr, targetPort, fake, packet, config)
            }
            BypassStrategy.UDP_NOISE_PAD -> {
                socket.send(packet)
                if (rnd.nextInt(100) < 30) {
                    val noise = ByteArray(rnd.nextInt(10, 50)) { rnd.nextInt(256).toByte() }
                    try { socket.send(DatagramPacket(noise, noise.size, targetAddr, targetPort)) } catch (e: Throwable) {}
                }
            }
            BypassStrategy.UDP_QUIC_PAD -> {
                // For QUIC, we pad the initial packet with noise to hide the version/SNI
                if (length > 200 && (data[offset].toInt() and 0xC0) == 0xC0) {
                    val padding = FakePacketHelper.buildUdpNoise(rnd.nextInt(256, 512))
                    val combined = data.copyOfRange(offset, offset + length) + padding
                    socket.send(DatagramPacket(combined, combined.size, targetAddr, targetPort))
                    // Occasional Version Negotiation noise
                    if (rnd.nextInt(100) < 20) {
                        val vn = FakePacketHelper.buildQuicVersionNegotiation()
                        socket.send(DatagramPacket(vn, vn.size, targetAddr, targetPort))
                    }
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.UDP_QUIC_SMART_SHADOW -> {
                // 1. Shadow Handshake (Fake QUIC Initial with low TTL)
                val isIpv6 = targetAddr is java.net.Inet6Address
                TtlHelper.setUdpTtl(socket, 3, isIpv6)
                val shadow = FakePacketHelper.buildQuicCryptoFake()
                try { socket.send(DatagramPacket(shadow, shadow.size, targetAddr, targetPort)) } catch (e: Throwable) {}
                delay(2)
                
                // 2. Real data reordered
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                if (length > 100) {
                    val split = length / 2
                    val part1 = data.copyOfRange(offset + split, offset + length)
                    val part2 = data.copyOfRange(offset, offset + split)
                    socket.send(DatagramPacket(part1, part1.size, targetAddr, targetPort))
                    delay(rnd.nextLong(1, 5))
                    socket.send(DatagramPacket(part2, part2.size, targetAddr, targetPort))
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.UDP_DNS_REORDER_HYBRID -> {
                // Combine DNS noise + reordering
                val isIpv6 = targetAddr is java.net.Inet6Address
                TtlHelper.setUdpTtl(socket, 2, isIpv6)
                val noise = FakePacketHelper.buildDnsFakeQuery("google.com")
                try { socket.send(DatagramPacket(noise, noise.size, targetAddr, targetPort)) } catch (e: Throwable) {}
                delay(1)
                
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                if (length > 20) {
                    val split = length - 10
                    val part1 = data.copyOfRange(offset + split, offset + length)
                    val part2 = data.copyOfRange(offset, offset + split)
                    socket.send(DatagramPacket(part1, part1.size, targetAddr, targetPort))
                    delay(2)
                    socket.send(DatagramPacket(part2, part2.size, targetAddr, targetPort))
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.QUIC_INITIAL_FRAGMENT -> {
                if (length > 200 && (data[offset].toInt() and 0xC0) == 0xC0) {
                    val split = 64
                    val part1 = data.copyOfRange(offset, offset + split)
                    val part2 = data.copyOfRange(offset + split, offset + length)
                    socket.send(DatagramPacket(part1, part1.size, targetAddr, targetPort))
                    delay(rnd.nextLong(1, 4))
                    socket.send(DatagramPacket(part2, part2.size, targetAddr, targetPort))
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.QUIC_INITIAL_PADDING_EXTREME -> {
                if (length > 200 && (data[offset].toInt() and 0xC0) == 0xC0) {
                    // Maximum allowed UDP size (to avoid fragmentation but maximize entropy)
                    val padding = FakePacketHelper.buildUdpNoise(rnd.nextInt(800, 1100))
                    val combined = data.copyOfRange(offset, offset + length) + padding
                    socket.send(DatagramPacket(combined, combined.size, targetAddr, targetPort))
                    
                    // Force a Version Negotiation desync
                    val vn = FakePacketHelper.buildQuicVersionNegotiation()
                    socket.send(DatagramPacket(vn, vn.size, targetAddr, targetPort))
                    
                    // Delay slightly to confuse timing analysis
                    delay(rnd.nextLong(2, 8))
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.UDP_FRAGMENT_SKEW -> {
                // Naive byte-level splitting breaks UDP because it's a datagram protocol.
                // Instead, we inject a short fake packet with low TTL before the real packet to confuse DPI state.
                if (length > 60) {
                    val fake = ByteArray(length / 2) { rnd.nextInt(256).toByte() }
                    val isIpv6 = targetAddr is java.net.Inet6Address
                    TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5), isIpv6)
                    socket.send(DatagramPacket(fake, fake.size, targetAddr, targetPort))
                    delay(config.delay1)
                    TtlHelper.setUdpTtl(socket, 64, isIpv6)
                    socket.send(packet)
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.PROTOCOL_CONFUSION_QUIC -> {
                val fake = FakePacketHelper.buildProtocolConfusion("QUIC")
                writeUdpWithFake(socket, targetAddr, targetPort, fake, packet, config)
            }
            BypassStrategy.PROTOCOL_CONFUSION_DTLS -> {
                val fake = FakePacketHelper.buildProtocolConfusion("DTLS")
                writeUdpWithFake(socket, targetAddr, targetPort, fake, packet, config)
            }
            BypassStrategy.UDP_STUTTER -> {
                delay(rnd.nextLong(5, 25))
                socket.send(packet)
            }
            BypassStrategy.UDP_GHOST_SKEW -> {
                val ghost = FakePacketHelper.buildUdpNoise(rnd.nextInt(32, 64))
                val isIpv6 = targetAddr is java.net.Inet6Address
                TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5), isIpv6)
                socket.send(DatagramPacket(ghost, ghost.size, targetAddr, targetPort))
                delay(config.delay1)
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                socket.send(packet)
            }
            BypassStrategy.UDP_TELEGRAM_FAKE -> {
                val fake = FakePacketHelper.buildUdpNoise(48)
                writeUdpWithFake(socket, targetAddr, targetPort, fake, packet, config)
            }
            BypassStrategy.UDP_QUIC_SKEW -> {
                val fake = FakePacketHelper.buildQuicInitialFake()
                val isIpv6 = targetAddr is java.net.Inet6Address
                TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5), isIpv6)
                socket.send(DatagramPacket(fake, fake.size, targetAddr, targetPort))
                delay(config.delay1)
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                socket.send(packet)
            }
            BypassStrategy.UDP_DATA_FRAG -> {
                if (length > 200) {
                    val half = length / 2
                    val p1 = data.copyOfRange(offset, offset + half)
                    val p2 = data.copyOfRange(offset + half, offset + length)
                    socket.send(DatagramPacket(p1, p1.size, targetAddr, targetPort))
                    delay(rnd.nextLong(1, 5))
                    
                    // Optional noise injection between fragments
                    if (ProxyStats.censorshipIntensity.value > 70) {
                         val randomNoise = FakePacketHelper.buildUdpNoise(rnd.nextInt(20, 60))
                         try {
                             TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 4), isIpv6)
                             socket.send(DatagramPacket(randomNoise, randomNoise.size, targetAddr, targetPort))
                             delay(rnd.nextLong(1, 3))
                         } catch (e: Throwable) {}
                         TtlHelper.setUdpTtl(socket, 64, isIpv6)
                    }
                    
                    socket.send(DatagramPacket(p2, p2.size, targetAddr, targetPort))
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.UDP_REORDER -> {
                // Handled in UdpTransportHandler with buffering
                socket.send(packet)
            }
            BypassStrategy.UDP_SKEW_ADVANCED -> {
                if (length > 50) {
                    // 1. Ghost Packet with Low TTL and different payload
                    val ghost = FakePacketHelper.buildUdpNoise(rnd.nextInt(16, 64))
                    TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 4), isIpv6)
                    socket.send(DatagramPacket(ghost, ghost.size, targetAddr, targetPort))
                    delay(rnd.nextLong(1, 3))
                    TtlHelper.setUdpTtl(socket, 64, isIpv6)
                    
                    // 2. Overlapping Fragmented Delivery
                    val split = rnd.nextInt(10, (length - 10).coerceAtLeast(11))
                    val p1 = data.copyOfRange(offset, offset + split)
                    val p2 = data.copyOfRange(offset + split - 5, offset + length) // 5 byte overlap
                    socket.send(DatagramPacket(p1, p1.size, targetAddr, targetPort))
                    delay(rnd.nextLong(1, 2))
                    socket.send(DatagramPacket(p2, p2.size, targetAddr, targetPort))
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.UDP_IP_ID_MANGLE -> {
                // We send a tiny noise packet with a random IP ID (if we could, but we can't)
                // instead we send a zero-byte packet or a tiny noise packet to perturb the state
                socket.send(packet)
                if (rnd.nextInt(100) < 40) {
                    val noise = FakePacketHelper.buildUdpNoise(rnd.nextInt(1, 5))
                    try { socket.send(DatagramPacket(noise, noise.size, targetAddr, targetPort)) } catch(e: Throwable) {}
                }
            }
            BypassStrategy.UDP_FAKE_TRAFFIC -> {
                // Send some random UDP noise to various destinations if we were allowed, 
                // but here we just send a fake to the target.
                val fake1 = FakePacketHelper.buildUdpNoise(rnd.nextInt(16, 48))
                TtlHelper.setUdpTtl(socket, 2, isIpv6)
                socket.send(DatagramPacket(fake1, fake1.size, targetAddr, targetPort))
                delay(config.delay1)
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                socket.send(packet)

                if (rnd.nextInt(100) < 25) {
                    val decoys = listOf("8.8.8.8", "1.1.1.1", "9.9.9.9", "185.199.108.153", "149.154.167.99")
                    try {
                        val decoyAddr = InetAddress.getByName(decoys.random())
                        val decoyPayload = if (rnd.nextBoolean()) FakePacketHelper.buildWireguardFake() else FakePacketHelper.buildOpenVpnFake()
                        socket.send(DatagramPacket(decoyPayload, decoyPayload.size, decoyAddr, if (rnd.nextBoolean()) 51820 else 1194))
                    } catch (e: Throwable) {}
                }
            }
            BypassStrategy.UDP_IP_FRAG -> {
                // Simulate fragmentation by sending the packet multiple times with low TTL
                // to trigger different code paths in the DPI reassembler.
                if (length > 100) {
                    val part = length / 2
                    val fake = data.copyOfRange(0, part)
                    TtlHelper.setUdpTtl(socket, 2, isIpv6)
                    socket.send(DatagramPacket(fake, fake.size, targetAddr, targetPort))
                    delay(1)
                }
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                socket.send(packet)
            }
            BypassStrategy.QUIC_INITIAL_FRAGMENT -> {
                if (length > 1000 && (data[offset].toInt() and 0xC0) == 0xC0) {
                    val p1 = data.copyOfRange(offset, offset + 150)
                    val p2 = data.copyOfRange(offset + 150, offset + length)
                    socket.send(DatagramPacket(p1, p1.size, targetAddr, targetPort))
                    delay(rnd.nextLong(1, 4))
                    socket.send(DatagramPacket(p2, p2.size, targetAddr, targetPort))
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.QUIC_VERSION_SKEW -> {
                if (length > 200 && (data[offset].toInt() and 0xC0) == 0xC0) {
                    val fakeVn = FakePacketHelper.buildQuicVersionNegotiation()
                    TtlHelper.setUdpTtl(socket, 3, isIpv6)
                    socket.send(DatagramPacket(fakeVn, fakeVn.size, targetAddr, targetPort))
                    delay(config.delay1)
                    TtlHelper.setUdpTtl(socket, 64, isIpv6)
                }
                socket.send(packet)
            }
            BypassStrategy.UDP_ZERO_LEN_SKEW -> {
                if (rnd.nextBoolean()) {
                    val zero = ByteArray(0)
                    socket.send(DatagramPacket(zero, 0, targetAddr, targetPort))
                    delay(1)
                }
                socket.send(packet)
            }
            BypassStrategy.TLS_SNI_REVERSE -> {
                // For UDP/DTLS we just send the packet
                socket.send(packet)
            }
            BypassStrategy.QUIC_INITIAL_FRAGMENTATION -> {
                if (length > 1000) {
                    val p1 = data.copyOfRange(offset, offset + 120)
                    val p2 = data.copyOfRange(offset + 120, offset + length)
                    socket.send(DatagramPacket(p1, p1.size, targetAddr, targetPort))
                    delay(rnd.nextLong(1, 3))
                    socket.send(DatagramPacket(p2, p2.size, targetAddr, targetPort))
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.QUIC_FORCE_FRAG -> {
                if (length > 100) {
                    val part1 = length / 3
                    val part2 = (length * 2) / 3
                    socket.send(DatagramPacket(data, offset, part1, targetAddr, targetPort))
                    delay(rnd.nextLong(1, 4))
                    socket.send(DatagramPacket(data, offset + part1, part2 - part1, targetAddr, targetPort))
                    delay(rnd.nextLong(1, 4))
                    socket.send(DatagramPacket(data, offset + part2, length - part2, targetAddr, targetPort))
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.QUIC_INITIAL_PADDING_EXTREME -> {
                if (packet.length > 1000) { // Likely a QUIC Initial
                    val fake = FakePacketHelper.buildQuicInitialExtremePadding()
                    TtlHelper.setUdpTtl(socket, 4, isIpv6)
                    socket.send(DatagramPacket(fake, fake.size, targetAddr, targetPort))
                    delay(config.delay1)
                    TtlHelper.setUdpTtl(socket, 64, isIpv6)
                    socket.send(packet)
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.QUIC_HANDSHAKE_SKEW -> {
                if (length > 200 && (data[offset].toInt() and 0xC0) == 0xC0) {
                    repeat(rnd.nextInt(2, 4)) {
                        val fake = FakePacketHelper.buildQuicInitialExtremePadding()
                        TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 4), isIpv6)
                        socket.send(DatagramPacket(fake, fake.size, targetAddr, targetPort))
                        delay(rnd.nextLong(1, 5))
                    }
                    TtlHelper.setUdpTtl(socket, 64, isIpv6)
                    socket.send(packet)
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.BYEBYEDPI_SIM -> {
                val fakeQuic = FakePacketHelper.buildQuicInitialFake()
                val noise = FakePacketHelper.buildUdpNoise(rnd.nextInt(64, 128))
                TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5), isIpv6)
                socket.send(DatagramPacket(fakeQuic, fakeQuic.size, targetAddr, targetPort))
                delay(1)
                socket.send(DatagramPacket(noise, noise.size, targetAddr, targetPort))
                delay(config.delay1)
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                socket.send(packet)
            }
            BypassStrategy.UDP_QUIC_PAD -> {
                val padding = FakePacketHelper.buildUdpNoise(rnd.nextInt(128, 512))
                val combined = data.copyOfRange(offset, offset + length) + padding
                socket.send(DatagramPacket(combined, combined.size, targetAddr, targetPort))
            }
            BypassStrategy.QUIC_INITIAL_FRAGMENT -> {
                if (length > 200 && (data[offset].toInt() and 0xC0) == 0xC0) {
                    val split = 64
                    val p1 = data.copyOfRange(offset, offset + split)
                    val p2 = data.copyOfRange(offset + split, offset + length)
                    socket.send(DatagramPacket(p1, p1.size, targetAddr, targetPort))
                    delay(rnd.nextLong(1, 3))
                    socket.send(DatagramPacket(p2, p2.size, targetAddr, targetPort))
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.UDP_SKEW_REVERSE -> {
                if (length > 40) {
                    val split = length / 2
                    val p1 = data.copyOfRange(offset, offset + split)
                    val p2 = data.copyOfRange(offset + split, offset + length)
                    // Send second part first
                    socket.send(DatagramPacket(p2, p2.size, targetAddr, targetPort))
                    delay(rnd.nextLong(1, 4))
                    socket.send(DatagramPacket(p1, p1.size, targetAddr, targetPort))
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
        if (length < 8) return false
        val s = String(data, 0, minOf(length, 16), Charsets.US_ASCII)
        return s.startsWith("GET ") || s.startsWith("POST ") || s.startsWith("HEAD ") || 
               s.startsWith("PUT ") || s.startsWith("DELETE ") || s.startsWith("OPTIONS ") || 
               s.startsWith("CONNECT ") || s.startsWith("HTTP/")
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

        // Adaptive Delay Tuning based on RTT
        val rtt = currentRttMs.value
        val adaptiveDelay = when {
            rtt < 40 -> rnd.nextLong(1, 2)
            rtt < 120 -> rnd.nextLong(2, 4)
            else -> rnd.nextLong(5, 12)
        }
        val effectiveDelay = if (config.delay1 > 0) config.delay1 else adaptiveDelay

        if (length <= 5 || TlsParser.isEchDetected(data, length)) {
            output.write(data, 0, length); output.flush(); return
        }

        try {
            socket.tcpNoDelay = true
        } catch (e: Throwable) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }

        // 1. Data Mangle Stage (Hybrid potential)
        var finalData = data
        var finalLen = length
        
        if (isProbableHttp(data, length)) {
            if (strategy == BypassStrategy.HTTP_METHOD_CASE_MANGLE || (strategy.family == StrategyFamily.HTTP && rnd.nextInt(100) < 20)) {
                finalData = FakePacketHelper.mangleHttpMethodCase(finalData, finalLen)
                finalLen = finalData.size
            }
            if (strategy == BypassStrategy.HTTP_HEADER_CASE_CHAOS) {
                finalData = FakePacketHelper.randomizeHeaderCase(finalData, finalLen)
                finalLen = finalData.size
            }
        }

        when (strategy) {
            BypassStrategy.TCP_SYN_FLOOD_FAKE -> {
                repeat(rnd.nextInt(2, 5)) {
                    val fake = FakePacketHelper.buildUdpNoise(rnd.nextInt(32, 64))
                    TtlHelper.setTtl(socket, rnd.nextInt(2, 4))
                    output.write(fake); output.flush()
                    delay(rnd.nextLong(1, 5))
                }
                TtlHelper.setTtl(socket, 64)
                output.write(finalData, 0, finalLen); output.flush()
            }
            BypassStrategy.TLS_CLIENT_HELLO_MULTI_PAD -> {
                val mod = FakePacketHelper.injectMultiTlsPadding(finalData, finalLen, rnd.nextInt(2, 5))
                output.write(mod); output.flush()
            }
            BypassStrategy.SNI_SPLIT -> {
                val offset = TlsParser.findSniOffset(finalData, finalLen, host)
                val split = if (offset != -1) offset + 1 else config.frag1.coerceIn(1, finalLen - 1)
                val safeSplit = split.coerceIn(1, finalLen - 1)
                output.write(finalData, 0, safeSplit); output.flush(); delay(effectiveDelay)
                output.write(finalData, safeSplit, finalLen - safeSplit); output.flush()
            }
            BypassStrategy.TLS_SNI_SYMMETRIC_SPLIT -> {
                val offset = TlsParser.findSniOffset(finalData, finalLen, host)
                val split = if (offset != -1 && host.isNotEmpty()) offset + (host.length / 2) else config.frag1.coerceIn(1, finalLen - 1)
                val safeSplit = split.coerceIn(1, finalLen - 1)
                output.write(finalData, 0, safeSplit); output.flush(); delay(effectiveDelay)
                output.write(finalData, safeSplit, finalLen - safeSplit); output.flush()
            }
            BypassStrategy.SNI_TRIPLE -> {
                val offset = TlsParser.findSniOffset(finalData, finalLen, host)
                if (offset != -1 && finalLen > offset + host.length + 1) {
                    val part1 = (host.length / 3).coerceAtLeast(1)
                    val part2 = (2 * host.length / 3).coerceAtLeast(part1 + 1)
                    
                    val s1 = offset + part1
                    val s2 = offset + part2
                    
                    output.write(finalData, 0, s1); output.flush(); delay(effectiveDelay)
                    output.write(finalData, s1, s2 - s1); output.flush(); delay(config.delay2.coerceAtLeast(effectiveDelay))
                    output.write(finalData, s2, finalLen - s2); output.flush()
                } else {
                    val s1 = (finalLen / 3).coerceIn(1, finalLen - 2)
                    val s2 = (2 * finalLen / 3).coerceIn(s1 + 1, finalLen - 1)
                    output.write(finalData, 0, s1); output.flush(); delay(effectiveDelay)
                    output.write(finalData, s1, s2 - s1); output.flush(); delay(config.delay2.coerceAtLeast(effectiveDelay))
                    output.write(finalData, s2, finalLen - s2); output.flush()
                }
            }
            BypassStrategy.TCP_WINDOW_SHAKE -> {
                try {
                    val originalSize = socket.receiveBufferSize
                    socket.receiveBufferSize = rnd.nextInt(128, 512)
                    output.write(finalData, 0, finalLen / 2); output.flush()
                    delay(rnd.nextLong(10, 50))
                    socket.receiveBufferSize = originalSize + rnd.nextInt(1, 1024)
                    output.write(finalData, finalLen / 2, finalLen - (finalLen / 2)); output.flush()
                } catch (e: Throwable) {
                    output.write(finalData, 0, finalLen); output.flush()
                }
            }
            BypassStrategy.TLS_SNI_NULL_EXT -> {
                val mod = FakePacketHelper.injectExtension(data, length, 0x0000, ByteArray(0))
                output.write(mod); output.flush()
            }
            BypassStrategy.TLS_SNI_OVERLAP_SKEW -> {
                val sni = host.toByteArray()
                val mod1 = FakePacketHelper.injectExtension(data, length, 0x0000, sni)
                val mod2 = FakePacketHelper.injectExtension(mod1, mod1.size, 0x0000, "google.com".toByteArray())
                output.write(mod2); output.flush()
            }
            BypassStrategy.TCP_DATA_REPETITION -> {
                try {
                    val split = (length / 2).coerceAtLeast(1)
                    output.write(data, 0, split); output.flush()
                    delay(config.delay1)
                    
                    // Duplicate part with low TTL
                    TtlHelper.setTtl(socket, 2)
                    output.write(data, 0, split); output.flush()
                    delay(1)
                    TtlHelper.setTtl(socket, 64)
                    
                    output.write(data, split, length - split); output.flush()
                } catch (e: Throwable) {
                    output.write(data, 0, length); output.flush()
                }
            }
            BypassStrategy.TCP_OVERLAP_SKEW -> {
                val offset = TlsParser.findSniOffset(data, length, host)
                val split = if (offset != -1) offset + 2 else config.frag1.coerceIn(1, length - 1)
                
                // 1. Part 1 (Real)
                output.write(data, 0, split); output.flush()
                
                // 2. Overlap with Fake (Low TTL)
                val overlapLen = minOf(length - split, 64)
                if (overlapLen > 0) {
                    val fake = FakePacketHelper.buildUdpNoise(overlapLen)
                    TtlHelper.setTtl(socket, rnd.nextInt(2, 4))
                    output.write(fake); output.flush()
                    delay(1)
                    TtlHelper.setTtl(socket, 64)
                }
                
                // 3. Part 2 (Real)
                delay(config.delay1)
                output.write(data, split, length - split); output.flush()
                
                // 4. Occasional extra noise
                if (rnd.nextInt(100) < 20) {
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                }
            }
            BypassStrategy.TCP_OVERLAP -> {
                val offset = TlsParser.findSniOffset(data, length, host)
                val split = if (offset != -1) offset + 1 else config.frag1.coerceIn(1, length - 1)
                
                // 1. Отправляем первую часть (Реальную)
                output.write(data, 0, split); output.flush()
                
                // 2. Отправляем OVERLAP (Ghost) часть с низким TTL
                // Она перекрывает следующие данные в очереди DPI, но не доходит до сервера
                val ghostLen = minOf(length - split, 48)
                if (ghostLen > 0) {
                    val ghost = FakePacketHelper.buildUdpNoise(ghostLen) // Мусорные данные
                    try {
                        TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
                        output.write(ghost); output.flush()
                        delay(1)
                        TtlHelper.setTtl(socket, 64)
                    } catch (e: Throwable) {}
                }
                
                // 3. Отправляем реальную вторую часть
                delay(config.delay1)
                output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.TCP_REORDER_CHAOS -> {
                val split = length / 2
                if (split > 0) {
                    // Симуляция изменения порядка: отправляем фейк на место начала, 
                    // затем реальный хвост, затем реальное начало.
                    try {
                        TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
                        output.write(data, 0, split); output.flush()
                        delay(1)
                        TtlHelper.setTtl(socket, 64)
                    } catch (e: Throwable) {}
                    
                    output.write(data, split, length - split); output.flush()
                    delay(config.delay1)
                    output.write(data, 0, split); output.flush()
                } else {
                    output.write(data, 0, length); output.flush()
                }
            }
            BypassStrategy.TLS_APP_DATA_SPLIT -> {
                // Если это не ClientHello, а уже зашифрованные данные (0x17)
                if (length > 5 && data[0] == 0x17.toByte()) {
                    val s1 = length / 3
                    val s2 = 2 * length / 3
                    output.write(data, 0, s1); output.flush(); delay(config.delay1)
                    output.write(data, s1, s2 - s1); output.flush(); delay(config.delay1)
                    output.write(data, s2, length - s2); output.flush()
                } else {
                    output.write(data, 0, length); output.flush()
                }
            }
            BypassStrategy.TCP_ZERO_WINDOW_STALL -> {
                // Имитация Zero Window: мы не можем напрямую менять окно через Socket API,
                // но можем задерживать отправку и делать микро-паузы, сбивая тайминги DPI.
                val s = length / 2
                output.write(data, 0, s); output.flush()
                delay(rnd.nextLong(200, 600)) // "Замирание"
                output.write(data, s, length - s); output.flush()
            }
            BypassStrategy.TLS_CLIENT_HELLO_CHOP -> {
                var pos = 0
                while (pos < length) {
                    val sz = rnd.nextInt(1, 4).coerceAtMost(length - pos)
                    output.write(data, pos, sz)
                    output.flush()
                    pos += sz
                    if (pos < length) delay(rnd.nextLong(1, 3))
                }
            }
            BypassStrategy.TLS_CHROME_HELLO_FAKE -> {
                val fake = FakePacketHelper.buildChromeHello("google.com")
                TtlHelper.setTtl(socket, config.fakeTtl)
                output.write(fake); output.flush()
                delay(config.delay1)
                TtlHelper.setTtl(socket, 64)
                val split = config.frag1.coerceIn(1, length - 1)
                output.write(data, 0, split); output.flush(); delay(config.delay2)
                output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.TLS_FIREFOX_HELLO_FAKE -> {
                val fake = FakePacketHelper.buildFirefoxHello("cloudflare.com")
                TtlHelper.setTtl(socket, config.fakeTtl)
                output.write(fake); output.flush()
                delay(config.delay1)
                TtlHelper.setTtl(socket, 64)
                val split = config.frag1.coerceIn(1, length - 1)
                output.write(data, 0, split); output.flush(); delay(config.delay2)
                output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.TLS_13_HELLO_FAKE -> {
                val fake = FakePacketHelper.buildTls13Hello("microsoft.com")
                TtlHelper.setTtl(socket, config.fakeTtl)
                output.write(fake); output.flush()
                delay(config.delay1)
                TtlHelper.setTtl(socket, 64)
                val split = config.frag1.coerceIn(1, length - 1)
                output.write(data, 0, split); output.flush(); delay(config.delay2)
                output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.GHOST_PACKETS, BypassStrategy.FAKE_PACKET -> {
                val fake = FakePacketHelper.buildFakeClientHello("bing.com", 80, 50, true)
                TtlHelper.setTtl(socket, config.fakeTtl)
                output.write(fake); output.flush()
                delay(config.delay1)
                TtlHelper.setTtl(socket, 64)
                
                // Fragment the real packet to bypass SNI matching if the fake packet didn't fully fool the DPI
                val offset = TlsParser.findSniOffset(data, length, host)
                val split = if (offset != -1) offset + 1 else config.frag1.coerceIn(1, length - 1)
                val safeSplit = split.coerceIn(1, length - 1)
                output.write(data, 0, safeSplit); output.flush(); delay(config.delay2)
                output.write(data, safeSplit, length - safeSplit); output.flush()
            }
            BypassStrategy.TLS_GREASE, BypassStrategy.TLS_EXTENSION_GREASE -> {
                val mod = FakePacketHelper.addTlsGreaseExtensions(data, length)
                val split = config.frag1.coerceIn(1, mod.size - 1)
                output.write(mod, 0, split); output.flush(); delay(config.delay1)
                output.write(mod, split, mod.size - split); output.flush()
            }
            BypassStrategy.TLS_CIPHER_SHUFFLE, BypassStrategy.TLS_EXT_SKEW, BypassStrategy.TLS_EXTENSION_SHUFFLE -> {
                val mod = FakePacketHelper.shuffleTlsExtensions(data, length)
                val split = config.frag1.coerceIn(1, mod.size - 1)
                output.write(mod, 0, split); output.flush(); delay(config.delay1)
                output.write(mod, split, mod.size - split); output.flush()
            }
            BypassStrategy.TLS_CLIENT_HELLO_PAD_EXTREME -> {
                val mod = FakePacketHelper.injectTlsPadding(data, length, java.util.concurrent.ThreadLocalRandom.current().nextInt(512, 1024))
                val split = config.frag1.coerceIn(1, mod.size - 1)
                output.write(mod, 0, split); output.flush(); delay(config.delay1)
                output.write(mod, split, mod.size - split); output.flush()
            }
            BypassStrategy.SNI_MANGLE, BypassStrategy.TLS_MIXED_CASE_SNI -> {
                val offset = TlsParser.findSniOffset(data, length, host)
                if (offset != -1 && host != null) {
                    val mod = data.copyOf(length)
                    // Mangle hostname case: example.com -> eXaMpLe.CoM
                    for (i in 0 until host.length) {
                        val c = host[i]
                        if (c.isLetter() && rnd.nextBoolean()) {
                            mod[offset + i] = if (c.isLowerCase()) c.uppercaseChar().code.toByte() else c.lowercaseChar().code.toByte()
                        }
                    }
                    val split = offset + 1
                    output.write(mod, 0, split); output.flush(); delay(config.delay1)
                    output.write(mod, split, length - split); output.flush()
                } else {
                    val split = config.frag1.coerceIn(1, length - 1)
                    output.write(data, 0, split); output.flush(); delay(config.delay1)
                    output.write(data, split, length - split); output.flush()
                }
            }
            BypassStrategy.HTTP_HOST_CASE_MANGLE -> {
                if (isProbableHttp(data, length)) {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val s = String(data, 0, headerEnd)
                        val modified = s.replace("Host:", "hOSt:", ignoreCase = true)
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
            BypassStrategy.TLS_REC_SPLIT, BypassStrategy.TLS_REC_MANGLE -> {
                if (length > 5 && data[0] == 0x16.toByte() && data[1] == 0x03.toByte()) {
                    // Advanced Record Splitting: split the handshake into multiple records
                    val handshakeLen = ((data[3].toInt() and 0xFF) shl 8) or (data[4].toInt() and 0xFF)
                    if (handshakeLen + 5 <= length) {
                        val splitPos = rnd.nextInt(1, handshakeLen)
                        
                        // Record 1
                        val header1 = data.copyOf(5)
                        header1[3] = ((splitPos shr 8) and 0xFF).toByte()
                        header1[4] = (splitPos and 0xFF).toByte()
                        output.write(header1)
                        output.write(data, 5, splitPos)
                        output.flush()
                        
                        delay(rnd.nextLong(1, 10))
                        
                        // Record 2
                        val header2 = data.copyOf(5)
                        val remaining = handshakeLen - splitPos
                        header2[3] = ((remaining shr 8) and 0xFF).toByte()
                        header2[4] = (remaining and 0xFF).toByte()
                        output.write(header2)
                        output.write(data, 5 + splitPos, remaining)
                        
                        // Write any trailing data (though usually there isn't any in a Client Hello packet)
                        if (length > handshakeLen + 5) {
                            output.write(data, handshakeLen + 5, length - (handshakeLen + 5))
                        }
                        output.flush()
                    } else {
                        output.write(data, 0, 5); output.flush(); delay(rnd.nextLong(2, 10))
                        output.write(data, 5, length - 5); output.flush()
                    }
                } else {
                    val split = 1; output.write(data, 0, split); output.flush(); delay(5)
                    output.write(data, split, length - split); output.flush()
                }
            }
            BypassStrategy.TLS_CLIENT_HELLO_CHOP -> {
                // Aggressive fragmentation: 1-2 bytes per packet for the start
                var offset = 0
                val limit = length.coerceAtMost(20)
                while (offset < limit) {
                    val sz = rnd.nextInt(1, 3)
                    val toWrite = minOf(sz, limit - offset)
                    output.write(data, offset, toWrite); output.flush()
                    offset += toWrite
                    delay(rnd.nextLong(1, 5))
                }
                if (offset < length) {
                    output.write(data, offset, length - offset); output.flush()
                }
            }
            BypassStrategy.TLS_HELLO_JUNK -> {
                output.write(data, 0, length); output.flush()
                delay(2)
                // Send some garbage after Hello - only works if server tolerates it or if it's a decoy
                output.write(FakePacketHelper.buildUdpNoise(rnd.nextInt(10, 40))); output.flush()
            }
            BypassStrategy.TLS_ALPN_SKEW -> {
                val mod = data.copyOf(length)
                // Find "h2" or "http/1.1" in ALPN and mangle it (if not encrypted)
                // Simple byte-level search/replace for common strings
                for (i in 0 until length - 2) {
                    if (mod[i] == 'h'.code.toByte() && mod[i+1] == '2'.code.toByte()) {
                        if (rnd.nextBoolean()) mod[i] = 'H'.code.toByte()
                    }
                }
                output.write(mod); output.flush()
            }
            BypassStrategy.TCP_URGENT_RANDOM, BypassStrategy.TCP_URGENT_SKEW -> {
                val split = config.frag1.coerceIn(1, length - 1)
                output.write(data, 0, split); output.flush()
                try {
                    socket.sendUrgentData(rnd.nextInt(256))
                } catch (e: Throwable) {}
                delay(config.delay1)
                output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.TCP_WINDOW_SIZE_SKEW -> {
                try {
                    val originalSize = socket.receiveBufferSize
                    socket.receiveBufferSize = 32 // Set very small window
                    val split = length / 2
                    output.write(data, 0, split); output.flush(); delay(config.delay1)
                    socket.receiveBufferSize = originalSize // Reset
                    output.write(data, split, length - split); output.flush()
                } catch (e: Throwable) {
                    output.write(data, 0, length); output.flush()
                }
            }
            BypassStrategy.TCP_FAST_OPEN_FAKE -> {
                // TFO fake: send a fake packet that looks like TFO attempt
                val fake = FakePacketHelper.buildTlsNoise(32)
                // TFO often involves an option in SYN, which we can't do here easily,
                // but we can send a payload that looks like a TFO data segment.
                TtlHelper.setTtl(socket, config.fakeTtl)
                output.write(fake); output.flush()
                delay(config.delay1)
                TtlHelper.setTtl(socket, 64)
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TCP_WINDOW_SIZE_CHAOS -> {
                try {
                    socket.sendBufferSize = rnd.nextInt(128, 4096)
                    output.write(data, 0, length / 2); output.flush()
                    delay(rnd.nextLong(1, 10))
                    socket.sendBufferSize = rnd.nextInt(4096, 65536)
                    output.write(data, length / 2, length - (length / 2)); output.flush()
                } catch (e: Throwable) {
                    output.write(data, 0, length); output.flush()
                }
            }
            BypassStrategy.TCP_ZERO_WINDOW_DESYNC -> {
                val split = (length / 2).coerceIn(1, length - 1)
                output.write(data, 0, split); output.flush()
                // We can't set window to 0 via API, but we can delay massively
                delay(rnd.nextLong(500, 1500))
                output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.TCP_REORDER_DESYNC -> {
                val split = (length / 2).coerceIn(1, length - 1)
                // Simulate out-of-order by sending part 2, then a fake part 1 (low TTL), then real part 1
                // Actually, sending part 2 first would still mean its sequence numbers are lower than part 1 if we use write()
                // So we MUST send part 1 first in terms of sequence numbers.
                
                // Real trick:
                // 1. Send Part 1 (Normal TTL)
                // 2. Send Part 2 (Low TTL) - DPI sees 1+2
                // 3. Send Part 2 (Normal TTL) - Receiver sees 1+2
                output.write(data, 0, split); output.flush()
                TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
                output.write(data, split, length - split); output.flush()
                delay(config.delay1)
                TtlHelper.setTtl(socket, 64)
                output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.TLS_RECORD_PADDING, BypassStrategy.TLS_HANDSHAKE_RANDOM_PADDING -> {
                val mod = FakePacketHelper.injectTlsPadding(data, length, rnd.nextInt(128, 512))
                output.write(mod); output.flush()
            }
            BypassStrategy.TLS_SESSION_ID_RAND -> {
                val mod = data.copyOf(length)
                // Find Session ID offset (if it exists)
                if (length > 43) {
                    val sidLen = mod[43].toInt() and 0xff
                    if (sidLen > 0 && sidLen <= 32 && 44 + sidLen <= length) {
                        for (i in 0 until sidLen) {
                            mod[44 + i] = rnd.nextInt(256).toByte()
                        }
                    }
                }
                output.write(mod); output.flush()
            }
            BypassStrategy.TCP_WINDOW_CLAMPING -> {
                try {
                    // Force a very small window to slow down the handshake and confuse DPI
                    socket.receiveBufferSize = rnd.nextInt(256, 1024)
                    socket.sendBufferSize = rnd.nextInt(256, 1024)
                } catch (e: Throwable) {}
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TCP_WINDOW_SIZE_SKEW, BypassStrategy.TCP_WINDOW_RESTRICT -> {
                try {
                    socket.sendBufferSize = rnd.nextInt(512, 1460)
                    socket.receiveBufferSize = rnd.nextInt(512, 1460)
                } catch (e: Throwable) {}
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TCP_TOS_MANGLE -> {
                try {
                    // Set Type of Service / Traffic Class to something unusual
                    socket.trafficClass = listOf(0x04, 0x08, 0x10, 0x02).random()
                } catch (e: Throwable) {}
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_MIXED_CASE_SNI -> {
                val offset = TlsParser.findSniOffset(data, length, host)
                if (offset != -1) {
                    val mod = data.copyOf(length)
                    for (i in offset until offset + host.length) {
                        if (rnd.nextBoolean() && mod[i].toChar().isLetter()) {
                            mod[i] = (mod[i].toInt() xor 0x20).toByte()
                        }
                    }
                    output.write(mod); output.flush()
                } else {
                    output.write(data, 0, length); output.flush()
                }
            }
            BypassStrategy.TLS_EXTENSION_GREASE, BypassStrategy.TLS_GREASE_SKEW -> {
                val mod = FakePacketHelper.injectTlsGrease(data, length)
                output.write(mod); output.flush()
            }
            BypassStrategy.TLS_CLIENT_HELLO_PAD, BypassStrategy.TLS_PAD -> {
                val mod = FakePacketHelper.injectTlsPadding(data, length, rnd.nextInt(64, 256))
                output.write(mod); output.flush()
            }
            BypassStrategy.HTTP_HOST_SPACE -> {
                if (!containsHostHeader(data, length)) {
                    output.write(data, 0, length); output.flush()
                } else {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val head = data.copyOf(headerEnd)
                        var found = false
                        for (i in 0 until head.size - 6) {
                            if (head[i] == 'H'.code.toByte() && head[i+1] == 'o'.code.toByte() && head[i+4] == ':'.code.toByte() && head[i+5] == ' '.code.toByte()) {
                                 val newHead = ByteArray(head.size + 1)
                                 System.arraycopy(head, 0, newHead, 0, i + 6)
                                 newHead[i+6] = ' '.code.toByte()
                                 System.arraycopy(head, i + 6, newHead, i + 7, head.size - (i + 6))
                                 output.write(newHead)
                                 output.write(data, headerEnd, length - headerEnd)
                                 output.flush()
                                 found = true
                                 break
                            }
                        }
                        if (!found) { output.write(data, 0, length); output.flush() }
                    } else {
                        output.write(data, 0, length); output.flush()
                    }
                }
            }
            BypassStrategy.HTTP_METHOD_FAKE -> {
                if (isProbableHttp(data, length)) {
                    val fake = "POST / HTTP/1.1\r\nHost: $host\r\nContent-Length: 10\r\nConnection: keep-alive\r\n\r\nFAKE_DATA\r\n".toByteArray()
                    TtlHelper.setTtl(socket, config.fakeTtl)
                    output.write(fake); output.flush()
                    delay(config.delay1)
                    TtlHelper.setTtl(socket, 64)
                    val split = config.frag1.coerceIn(1, length - 1)
                    output.write(data, 0, split); output.flush(); delay(config.delay2)
                    output.write(data, split, length - split); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_AUTH_RANDOM -> {
                if (isProbableHttp(data, length)) {
                    val header = "Authorization: Basic ${java.util.Base64.getEncoder().encodeToString(rnd.nextLong().toString().toByteArray())}\r\n"
                    injectHeaderAfterFirstLine(data, length, header.toByteArray(), output)
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_HEADER_FUZZING -> {
                if (isProbableHttp(data, length)) {
                    val fuzz = "X-Fuzz-${rnd.nextInt(1000)}: ${rnd.nextLong()}\r\n"
                    injectHeaderAfterFirstLine(data, length, fuzz.toByteArray(), output)
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_VERSION_SKEW -> {
                if (isProbableHttp(data, length)) {
                    val mod = data.copyOf(length)
                    for (i in 0 until length - 8) {
                        if (mod[i] == 'H'.code.toByte() && mod[i+1] == 'T'.code.toByte() && mod[i+2] == 'T'.code.toByte() && mod[i+3] == 'P'.code.toByte() && mod[i+4] == '/'.code.toByte() && mod[i+5] == '1'.code.toByte() && mod[i+6] == '.'.code.toByte() && mod[i+7] == '1'.code.toByte()) {
                            mod[i+7] = '0'.code.toByte() // HTTP/1.1 -> HTTP/1.0
                            break
                        }
                    }
                    output.write(mod); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_RST_FAKE -> {
                // Send some junk data with low TTL to poison DPI state
                val ghost = FakePacketHelper.buildFakeTcpRst()
                TtlHelper.setTtl(socket, rnd.nextInt(2, 4))
                output.write(ghost); output.flush()
                delay(config.delay1)
                TtlHelper.setTtl(socket, 64)
                val split = config.frag1.coerceIn(1, length - 1)
                output.write(data, 0, split); output.flush(); delay(config.delay2)
                output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.TCP_KEEP_ALIVE_FAKE -> {
                // Send zero-length data segment with low TTL
                val keep = FakePacketHelper.buildFakeTcpKeepAlive()
                TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
                output.write(keep); output.flush()
                delay(2)
                TtlHelper.setTtl(socket, 64)
                val split = config.frag1.coerceIn(1, length - 1)
                output.write(data, 0, split); output.flush(); delay(config.delay2)
                output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.PROTOCOL_CONFUSION_SSH -> {
                val fake = FakePacketHelper.buildProtocolConfusion("SSH")
                writeWithFake(socket, output, fake, data, length, config)
            }
            BypassStrategy.PROTOCOL_CONFUSION_BITTORRENT -> {
                val fake = FakePacketHelper.buildProtocolConfusion("BITTORRENT")
                writeWithFake(socket, output, fake, data, length, config)
            }
            BypassStrategy.PROTOCOL_CONFUSION_HTTP -> {
                val fake = FakePacketHelper.buildProtocolConfusion("HTTP")
                writeWithFake(socket, output, fake, data, length, config)
            }
            BypassStrategy.WS_HANDSHAKE_FAKE -> {
                val fake = FakePacketHelper.buildFakeWebSocketHandshake(host)
                writeWithFake(socket, output, fake, data, length, config)
            }
            BypassStrategy.SSH_HANDSHAKE_FAKE -> {
                val fake = FakePacketHelper.buildSshHandshake()
                writeWithFake(socket, output, fake, data, length, config)
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
            BypassStrategy.TCP_GHOST_SKEW -> {
                val ghost = FakePacketHelper.buildTlsNoise(rnd.nextInt(64, 128))
                TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
                output.write(ghost); output.flush()
                delay(config.delay1)
                TtlHelper.setTtl(socket, 64)
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TCP_ACK_DELAY -> {
                val split = (length / 2).coerceIn(1, length - 1)
                output.write(data, 0, split); output.flush()
                delay(rnd.nextLong(100, 300))
                output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.TCP_RANDOM_PADDING -> {
                output.write(data, 0, length); output.flush()
                val padding = FakePacketHelper.buildUdpNoise(rnd.nextInt(32, 256))
                TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
                output.write(padding); output.flush()
                TtlHelper.setTtl(socket, 64)
            }
            BypassStrategy.OOB_DESYNC -> {
                val split = rnd.nextInt(1, length.coerceAtMost(5))
                output.write(data, 0, split); output.flush()
                try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                delay(config.delay1); output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.HTTP_RANGE_SKEW -> {
                if (!isProbableHttp(data, length)) {
                    output.write(data, 0, length); output.flush()
                } else {
                    injectHeaderAfterFirstLine(data, length, FAKE_RANGE_HEADER, output)
                }
            }
            BypassStrategy.CHAOS -> {
                val rndVal = rnd.nextInt(5)
                when (rndVal) {
                    0 -> { // Extreme Multi-fragmentation
                        val count = rnd.nextInt(5, 12)
                        for (i in 0 until count) {
                            val start = i * (length / count)
                            val end = if (i == count - 1) length else (i + 1) * (length / count)
                            if (end > start) {
                                output.write(data, start, end - start); output.flush()
                                delay(rnd.nextLong(1, 4))
                                if (rnd.nextInt(100) < 20) { 
                                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                                }
                            }
                        }
                    }
                    1 -> { // SNI Split + Fake Padding + OOB
                        val offset = TlsParser.findSniOffset(data, length, host)
                        if (offset != -1) {
                            output.write(data, 0, offset + 1); output.flush()
                            try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                            delay(rnd.nextLong(20, 80))
                            output.write(data, offset + 1, length - (offset + 1)); output.flush()
                        } else {
                            output.write(data, 0, length); output.flush()
                        }
                    }
                    2 -> { // Window Shake
                         try { socket.receiveBufferSize = rnd.nextInt(512, 2048) } catch (e: Throwable) {}
                         val split = (length / 2).coerceIn(1, (length - 1).coerceAtLeast(1))
                         output.write(data, 0, split); output.flush(); delay(config.delay1)
                         output.write(data, split, length - split); output.flush()
                    }
                    3 -> { // SNI Multi-Overlap
                        val offset = TlsParser.findSniOffset(data, length, host)
                        if (offset != -1) {
                            output.write(data, 0, offset + 1); output.flush()
                            TtlHelper.setTtl(socket, 2)
                            output.write(FakePacketHelper.buildTlsNoise(16)); output.flush()
                            TtlHelper.setTtl(socket, 64)
                            delay(10)
                            output.write(data, offset, length - offset); output.flush()
                        } else {
                            output.write(data, 0, length); output.flush()
                        }
                    }
                    else -> { // TCP REORDER Simulation
                        val split = (length / 2).coerceIn(1, (length - 1).coerceAtLeast(1))
                        output.write(data, split, length - split); output.flush()
                        delay(config.delay1)
                        output.write(data, 0, split); output.flush()
                    }
                }
            }
            BypassStrategy.TLS_MULTI_FRAG, BypassStrategy.FRAGMENT_MULTI -> {
                val count = rnd.nextInt(6, 12)
                for (i in 0 until count) {
                    val start = i * (length / count)
                    val end = if (i == count - 1) length else (i + 1) * (length / count)
                    if (end > start) {
                        output.write(data, start, end - start); output.flush()
                        delay(rnd.nextLong(1, 4))
                    }
                }
            }
            BypassStrategy.TCP_ZERO_WINDOW_STALL -> {
                val split = (length / 2).coerceIn(1, length - 1)
                output.write(data, 0, split); output.flush()
                delay(rnd.nextLong(1500, 4000))
                output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.SLOW_SEND -> {
                for (i in 0 until length) {
                    output.write(data[i].toInt()); output.flush()
                    delay(rnd.nextLong(5, 20))
                }
            }
            BypassStrategy.TCP_DATA_REPETITION -> {
                val split = (length / 2).coerceIn(1, length - 1)
                output.write(data, 0, split); output.flush()
                // Decoy with same data
                TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
                output.write(data, 0, split); output.flush()
                delay(config.delay1)
                TtlHelper.setTtl(socket, 64)
                output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.HTTP2_PREAMBLE_FAKE -> {
                val fake = FakePacketHelper.buildHttp2PreambleFake()
                TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
                output.write(fake); output.flush()
                delay(config.delay1)
                TtlHelper.setTtl(socket, 64)
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_MULTI_SNI -> {
                val multiSni = FakePacketHelper.buildMultiSniHello(host)
                output.write(multiSni); output.flush()
            }
            BypassStrategy.BYEBYEDPI_SIM -> {
                try {
                    val sniOffset = TlsParser.findSniOffset(data, length, host)
                    
                    if (sniOffset != -1) {
                        // 1. Ghost Handshake (fake packet with low TTL to poison DPI session)
                        try {
                            TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
                            val ghost = if (rnd.nextBoolean()) FakePacketHelper.buildTlsNoise(rnd.nextInt(128, 256)) else FakePacketHelper.buildEchFakeRecord(host)
                            output.write(ghost); output.flush()
                            delay(2)
                            TtlHelper.setTtl(socket, 64)
                        } catch (e: Throwable) {}

                        // 2. Fragmented Real Handshake with OOB and overlapping
                        val split1 = sniOffset + 1
                        val split2 = sniOffset + (if (host.isNotEmpty()) host.length / 2 else 2)
                        
                        // First part
                        output.write(data, 0, split1); output.flush()
                        
                        // OOB byte desync
                        if (rnd.nextBoolean()) {
                            try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                        }
                        
                        delay(config.delay1)
                        
                        // Fake overlapping segment
                        try {
                            TtlHelper.setTtl(socket, 3)
                            output.write(FakePacketHelper.buildUdpNoise(split2 - split1)); output.flush()
                            delay(1)
                            TtlHelper.setTtl(socket, 64)
                        } catch (e: Throwable) {}

                        // Second part
                        output.write(data, split1, split2 - split1); output.flush()
                        delay(config.delay2)
                        
                        // Rest
                        output.write(data, split2, length - split2); output.flush()
                    } else {
                        // Aggressive fragmentation fallback
                        val s1 = (length / 3).coerceIn(1, (length - 2).coerceAtLeast(1))
                        output.write(data, 0, s1); output.flush(); delay(config.delay1)
                        if (length > s1) {
                            output.write(data, s1, (length - s1) / 2); output.flush(); delay(config.delay2)
                            output.write(data, s1 + (length - s1) / 2, length - (s1 + (length - s1) / 2)); output.flush()
                        }
                    }
                } catch (e: Throwable) {
                    output.write(data, 0, length); output.flush()
                }
            }
            BypassStrategy.TCP_HANDSHAKE_CHAOS -> {
                val split = (length / 3).coerceIn(1, length - 2)
                output.write(data, 0, split); output.flush()
                delay(rnd.nextLong(20, 100))
                output.write(data, split, split); output.flush()
                delay(rnd.nextLong(1, 10))
                output.write(data, 2 * split, length - 2 * split); output.flush()
            }
            BypassStrategy.TCP_OOB_SEGMENTATION -> {
                val split = (length / 2).coerceIn(1, length - 1)
                output.write(data, 0, split); output.flush()
                try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                delay(config.delay1)
                val remaining = length - split
                if (remaining > 10) {
                    val s2 = remaining / 2
                    output.write(data, split, s2); output.flush(); delay(5)
                    output.write(data, split + s2, remaining - s2); output.flush()
                } else {
                    output.write(data, split, remaining); output.flush()
                }
            }
            BypassStrategy.TCP_REORDER_SIM -> {
                val split = (length / 2).coerceIn(1, length - 1)
                // Simulate reordering by sending part 1, then part 2 with a delay and some fake overlap
                output.write(data, 0, split); output.flush()
                TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
                output.write(data, 0, split); output.flush() // Fake overlap
                delay(config.delay1)
                TtlHelper.setTtl(socket, 64)
                output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.HTTP_CHUNKED_FAKE -> {
                if (isProbableHttp(data, length)) {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                         output.write(data, 0, headerEnd); output.flush()
                         val fakeChunk = "1\r\nX\r\n".toByteArray()
                         TtlHelper.setTtl(socket, 3)
                         output.write(fakeChunk); output.flush()
                         delay(1)
                         TtlHelper.setTtl(socket, 64)
                         output.write(data, headerEnd, length - headerEnd); output.flush()
                    } else {
                        output.write(data, 0, length); output.flush()
                    }
                } else {
                    output.write(data, 0, length); output.flush()
                }
            }
            BypassStrategy.TLS_SNI_OVERLAP_SKEW -> {
                val offset = TlsParser.findSniOffset(data, length, host)
                if (offset != -1) {
                    val head = offset + 2
                    output.write(data, 0, head); output.flush()
                    
                    val fakeSni = FakePacketHelper.buildUdpNoise(host.length)
                    TtlHelper.setTtl(socket, rnd.nextInt(2, 4))
                    output.write(fakeSni); output.flush()
                    delay(1)
                    TtlHelper.setTtl(socket, 64)
                    
                    delay(config.delay1)
                    output.write(data, head, length - head); output.flush()
                } else {
                    output.write(data, 0, length); output.flush()
                }
            }
            BypassStrategy.TLS_ECH_FAKE -> {
                val fakeEch = FakePacketHelper.buildFakeEchExtension()
                val mod = FakePacketHelper.injectExtension(data, length, 0xfe0d, fakeEch)
                output.write(mod); output.flush()
            }
            BypassStrategy.TLS_REC_CHOP -> {
                if (length > 5 && data[0] == 0x16.toByte()) {
                    val bodyLen = ((data[3].toInt() and 0xFF) shl 8) or (data[4].toInt() and 0xFF)
                    if (bodyLen + 5 <= length) {
                        var pos = 5
                        while (pos < 5 + bodyLen) {
                            val chunk = rnd.nextInt(1, 5).coerceAtMost(5 + bodyLen - pos)
                            val header = data.copyOfRange(0, 5)
                            header[3] = ((chunk shr 8) and 0xFF).toByte()
                            header[4] = (chunk and 0xFF).toByte()
                            output.write(header); output.write(data, pos, chunk); output.flush()
                            pos += chunk
                            delay(rnd.nextLong(1, 3))
                        }
                    } else {
                        output.write(data, 0, length); output.flush()
                    }
                } else {
                     output.write(data, 0, length); output.flush()
                }
            }
            BypassStrategy.HTTP_METHOD_SPACE_MANGLE -> {
                if (isProbableHttp(data, length)) {
                    val mod = FakePacketHelper.addSpaceToHttpMethod(data, length)
                    output.write(mod); output.flush()
                } else {
                    output.write(data, 0, length); output.flush()
                }
            }
            BypassStrategy.HTTP_HOST_DOT_MANGLE -> {
                if (isProbableHttp(data, length)) {
                    val mod = FakePacketHelper.addDotToHost(data, length)
                    output.write(mod); output.flush()
                } else {
                    output.write(data, 0, length); output.flush()
                }
            }
            BypassStrategy.TCP_WINDOW_RESIZE_PACING -> {
                try {
                    val p1 = length / 2
                    socket.sendBufferSize = 128
                    output.write(data, 0, p1); output.flush()
                    delay(config.delay1.coerceAtLeast(5))
                    socket.sendBufferSize = 65535
                    output.write(data, p1, length - p1); output.flush()
                } catch (e: Throwable) {
                    output.write(data, 0, length); output.flush()
                }
            }
            BypassStrategy.TCP_KEEPALIVE_SKEW -> {
                try {
                    socket.keepAlive = true
                    val fake = FakePacketHelper.buildUdpNoise(1)
                    TtlHelper.setTtl(socket, 2)
                    output.write(fake); output.flush()
                    delay(1)
                    TtlHelper.setTtl(socket, 64)
                    output.write(data, 0, length); output.flush()
                } catch (e: Throwable) {
                    output.write(data, 0, length); output.flush()
                }
            }
            BypassStrategy.TCP_URGENT_DESYNC -> {
                val split = (length / 2).coerceIn(1, length - 1)
                output.write(data, 0, split); output.flush()
                try {
                    socket.sendUrgentData(rnd.nextInt(256))
                    delay(1)
                } catch (e: Throwable) {}
                output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.TLS_REHANDSHAKE_FAKE, BypassStrategy.TLS_SNI_SKEW, BypassStrategy.TCP_FAST_RETRANSMIT_SIM, BypassStrategy.TCP_REORDER_CHAOS, BypassStrategy.TLS_LEGACY_HELLOS, BypassStrategy.TLS_SESSION_TICKET_SKEW, BypassStrategy.TLS_0RTT_FAKE, BypassStrategy.TLS_COMPRESSION_FAKE, BypassStrategy.HTTP_PIPELINE_FAKE -> {
                val split = (length / 2).coerceIn(1, length - 1)
                output.write(data, 0, split); output.flush(); delay(config.delay1)
                output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.TCP_DATA_OOB_SKEW -> {
                var pos = 0
                while (pos < length) {
                    val sz = rnd.nextInt(10, 50).coerceAtMost(length - pos)
                    output.write(data, pos, sz); output.flush()
                    pos += sz
                    if (pos < length && rnd.nextInt(100) < 30) {
                        try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                        delay(rnd.nextLong(1, 10))
                    }
                }
            }
            BypassStrategy.TCP_SACK_FAKE -> {
                if (length > 20) {
                    val part = length / 2
                    output.write(data, 0, part); output.flush()
                    // Simulate SACK by sending a tiny piece with urgent data
                    try { socket.sendUrgentData(0) } catch (e: Throwable) {}
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
            BypassStrategy.TLS_CLIENT_HELLO_REORDER, BypassStrategy.TLS_CLIENT_HELLO_SHUFFLE -> {
                if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                    val shuffled = FakePacketHelper.shuffleTlsExtensions(data, length)
                    output.write(shuffled); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_RECORD_FRAGMENTATION -> {
                if (length > 5 && (data[0] == 0x16.toByte() || data[0] == 0x17.toByte())) {
                    val head = 5
                    val bodyLen = length - head
                    val maxChunk = if (ProxyStats.censorshipIntensity.value > 80) 10 else 40
                    var sent = 0
                    while (sent < bodyLen) {
                        val cur = rnd.nextInt(5, maxChunk).coerceAtMost(bodyLen - sent)
                        val record = ByteArray(5 + cur)
                        record[0] = data[0]; record[1] = data[1]; record[2] = data[2]
                        record[3] = (cur shr 8).toByte(); record[4] = (cur and 0xFF).toByte()
                        System.arraycopy(data, head + sent, record, 5, cur)
                        output.write(record); output.flush()
                        sent += cur
                        if (sent < bodyLen) delay(rnd.nextLong(1, 3))
                    }
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_HOST_REORDER -> {
                if (isProbableHttp(data, length)) {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val head = String(data, 0, headerEnd, Charsets.US_ASCII)
                        val lines = head.split("\r\n").toMutableList()
                        if (lines.size > 3) {
                            val first = lines.removeAt(0) // Keep GET/POST line first
                            // Remove empty line at end if exists
                            if (lines.last().isEmpty()) lines.removeAt(lines.size - 1)
                            
                            val hostIdx = lines.indexOfFirst { it.startsWith("Host:", ignoreCase = true) }
                            if (hostIdx != -1) {
                                val hostLine = lines.removeAt(hostIdx)
                                lines.shuffle()
                                // Place host line randomly but not first
                                lines.add(rnd.nextInt(lines.size + 1), hostLine)
                                lines.add(0, first)
                                val newHead = lines.joinToString("\r\n") + "\r\n\r\n"
                                output.write(newHead.toByteArray(Charsets.US_ASCII))
                                output.write(data, headerEnd, length - headerEnd)
                                output.flush()
                                return
                            }
                        }
                    }
                }
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.UDP_NOISE_PAD -> {
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_RECORD_PADDING -> {
                val padded = FakePacketHelper.padTlsRecord(finalData, finalLen, 1400)
                output.write(padded); output.flush()
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
            BypassStrategy.TCP_TOS_MANGLE -> {
                try { socket.trafficClass = 0x08 } catch (e: Throwable) {}
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.HTTP_KEEP_ALIVE_FAKE -> {
                if (isProbableHttp(data, length)) {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val request = String(data, 0, headerEnd, Charsets.US_ASCII)
                        val modified = request.replace("\r\n\r\n", "\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5, max=1000\r\n\r\n")
                        output.write(modified.toByteArray(Charsets.US_ASCII))
                        output.write(data, headerEnd, length - headerEnd)
                        output.flush()
                        return
                    }
                }
                val keepAlive = "OPTIONS * HTTP/1.1\r\nHost: $host\r\nConnection: keep-alive\r\n\r\n".toByteArray()
                output.write(keepAlive); output.flush(); delay(config.delay1)
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.CHAOS -> {
                // Duplicate CHAOS removed
            }
            BypassStrategy.TLS_CLIENT_HELLO_GREASE_RANDOM -> {
                if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                    val mangled = data.copyOf()
                    // Randomize GREASE values in ClientHello if found (heuristic)
                    for (i in 44 until length - 2) {
                        if (mangled[i] == mangled[i+1] && (mangled[i].toInt() and 0x0F) == 0x0A) {
                             mangled[i] = rnd.nextInt(256).toByte()
                             mangled[i+1] = rnd.nextInt(256).toByte()
                        }
                    }
                    output.write(mangled); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_WINDOW_SIZE_CHAOS -> {
                try {
                    socket.sendBufferSize = rnd.nextInt(256, 4096)
                    socket.receiveBufferSize = rnd.nextInt(256, 4096)
                } catch (e: Throwable) {}
                val count = rnd.nextInt(3, 8)
                for (i in 0 until count) {
                    val start = i * (length / count)
                    val end = if (i == count - 1) length else (i + 1) * (length / count)
                    if (end > start) {
                        output.write(data, start, end - start); output.flush()
                        delay(rnd.nextLong(1, 10))
                    }
                }
            }
            BypassStrategy.TCP_MSS_CLUMPING -> {
                val mss = rnd.nextInt(400, 800)
                var offset = 0
                while (offset < length) {
                    val sz = minOf(mss, length - offset)
                    output.write(data, offset, sz); output.flush()
                    offset += sz
                    if (offset < length) delay(rnd.nextLong(2, 5))
                }
            }
            BypassStrategy.TLS_SNI_SPLIT -> {
                val offset = TlsParser.findSniOffset(data, length, host)
                if (offset != -1) {
                    output.write(data, 0, offset + 1); output.flush()
                    delay(rnd.nextLong(20, 100))
                    output.write(data, offset + 1, length - (offset + 1)); output.flush()
                } else {
                    val split = (length / 2).coerceIn(1, length - 1)
                    output.write(data, 0, split); output.flush()
                    delay(config.delay1)
                    output.write(data, split, length - split); output.flush()
                }
            }
            BypassStrategy.HTTP_HOST_TAB_MANGLE -> {
                if (isProbableHttp(data, length)) {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val head = String(data, 0, headerEnd, Charsets.US_ASCII)
                        val modified = head.replace("Host:", "Host:\t", ignoreCase = true)
                        output.write(modified.toByteArray(Charsets.US_ASCII))
                        output.write(data, headerEnd, length - headerEnd)
                        output.flush()
                    } else { output.write(data, 0, length); output.flush() }
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_METHOD_SPACE_MANGLE -> {
                if (isProbableHttp(data, length)) {
                    val firstSpace = data.indexOf(' '.code.toByte())
                    if (firstSpace != -1 && firstSpace < 10) {
                        output.write(data, 0, firstSpace)
                        output.write(' '.code); output.write(' '.code) // Double space
                        output.write(data, firstSpace + 1, length - (firstSpace + 1))
                        output.flush()
                    } else { output.write(data, 0, length); output.flush() }
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_SNI_NULL_EXT -> {
                if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                    val mod = FakePacketHelper.injectExtension(data, length, 0x0000, ByteArray(0))
                    output.write(mod); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_SESSION_ID_MANGLE -> {
                if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                    val mod = FakePacketHelper.mangleSessionId(data, length)
                    output.write(mod); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.ECH_FRAG -> {
                if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                    output.write(data, 0, 5); output.flush(); delay(rnd.nextLong(1, 3))
                    output.write(data, 5, 6); output.flush(); delay(rnd.nextLong(1, 3))
                    output.write(data, 11, length - 11); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_CLIENT_HELLO_PAD_EXTREME -> {
                if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                    val pad = ByteArray(rnd.nextInt(512, 1024)).apply { rnd.nextBytes(this) }
                    val mod = FakePacketHelper.injectExtension(data, length, 0x0015, pad)
                    output.write(mod); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_HOST_SMUGGLE -> {
                if (isProbableHttp(data, length)) {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val head = String(data, 0, headerEnd, Charsets.US_ASCII)
                        val modified = head.replace("Host:", " Host:", ignoreCase = true) // Space before Host
                        output.write(modified.toByteArray(Charsets.US_ASCII))
                        output.write(data, headerEnd, length - headerEnd)
                        output.flush()
                    } else { output.write(data, 0, length); output.flush() }
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_HOST_REVERSE -> {
                if (isProbableHttp(data, length)) {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val head = String(data, 0, headerEnd, Charsets.US_ASCII)
                        val lines = head.split("\r\n").toMutableList()
                        val hostIdx = lines.indexOfFirst { it.startsWith("Host:", ignoreCase = true) }
                        if (hostIdx != -1) {
                            val hostLine = lines.removeAt(hostIdx)
                            lines.add(1, hostLine) // Move Host to be the second line (after Request-Line)
                            val newHead = lines.joinToString("\r\n")
                            output.write(newHead.toByteArray(Charsets.US_ASCII))
                            output.write(data, headerEnd, length - headerEnd)
                            output.flush()
                        } else { output.write(data, 0, length); output.flush() }
                    } else { output.write(data, 0, length); output.flush() }
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_CONNECTION_CLOSE_SKEW -> {
                if (isProbableHttp(data, length)) {
                    val fakeHeader = "Connection: keep-alive\r\n".toByteArray()
                    TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
                    injectHeaderAfterFirstLine(data, length, fakeHeader, output)
                    delay(config.delay1)
                    TtlHelper.setTtl(socket, 64)
                    output.write(data, 0, length); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_WINDOW_CLAMPING -> {
                try {
                    socket.receiveBufferSize = rnd.nextInt(512, 1024)
                } catch (e: Throwable) {}
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TLS_CLIENT_HELLO_SHUFFLE -> {
                if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                    val mod = FakePacketHelper.shuffleTlsExtensions(data, length)
                    output.write(mod); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_MULTI_LINE_MANGLE -> {
                if (isProbableHttp(data, length)) {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val head = String(data, 0, headerEnd, Charsets.US_ASCII)
                        val modified = head.replace("\r\n", "\r\n ", ignoreCase = true) // Space at start of continuation lines
                        output.write(modified.toByteArray(Charsets.US_ASCII))
                        output.write(data, headerEnd, length - headerEnd)
                        output.flush()
                    } else { output.write(data, 0, length); output.flush() }
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_URGENT_SKEW -> {
                val split = (length / 2).coerceAtLeast(1)
                output.write(data, 0, split)
                try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                output.flush()
                delay(config.delay1)
                output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.TCP_ACK_DELAY -> {
                output.write(data, 0, length); output.flush()
                // Throttling slightly to influence ACK timing
                delay(rnd.nextLong(2, 10))
            }
            BypassStrategy.HTTP_HOST_FOLDING -> {
                if (isProbableHttp(data, length)) {
                    val headEnd = findHeaderEnd(data, length)
                    if (headEnd != -1) {
                        val head = String(data, 0, headEnd, Charsets.US_ASCII)
                        // folding: Host: example.com -> Host:\r\n example.com
                        val modified = head.replace("Host:", "Host:\r\n ", ignoreCase = true)
                        output.write(modified.toByteArray(Charsets.US_ASCII))
                        output.write(data, headEnd, length - headEnd)
                        output.flush()
                    } else { output.write(data, 0, length); output.flush() }
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_HANDSHAKE_CHAOS -> {
                // Chaotic write pattern: 1 byte, delay, urgent data, rest
                output.write(data, 0, 1); output.flush()
                delay(rnd.nextLong(1, 5))
                try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                output.write(data, 1, length - 1); output.flush()
            }
            BypassStrategy.TCP_MSS_CLAMPER -> {
                // Simulate small MSS by fragmenting all writes into small chunks
                var pos = 0
                val chunkSize = rnd.nextInt(128, 512)
                while (pos < length) {
                    val len = minOf(chunkSize, length - pos)
                    output.write(data, pos, len)
                    output.flush()
                    pos += len
                    if (pos < length) delay(rnd.nextLong(1, 3))
                }
            }
            BypassStrategy.TLS_ECH_FAKE -> {
                if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                    val mod = FakePacketHelper.injectExtension(data, length, 0xfe0d, FakePacketHelper.buildUdpNoise(rnd.nextInt(128, 256)))
                    output.write(mod); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_SEGMENT_DESYNC -> {
                try {
                    val split = (length / 2).coerceIn(1, (length - 1).coerceAtLeast(1))
                    output.write(data, 0, split); output.flush()
                    // Overlap with junk
                    TtlHelper.setTtl(socket, rnd.nextInt(2, 4))
                    output.write(FakePacketHelper.buildUdpNoise(split)); output.flush()
                    delay(1)
                    TtlHelper.setTtl(socket, 64)
                    output.write(data, split, length - split); output.flush()
                } catch(e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.PROTOCOL_CONFUSION_REDIS -> {
                val fake = FakePacketHelper.buildProtocolConfusion("REDIS")
                writeWithFake(socket, output, fake, data, length, config)
            }
            BypassStrategy.PROTOCOL_CONFUSION_MEMCACHED -> {
                val fake = FakePacketHelper.buildProtocolConfusion("MEMCACHED")
                writeWithFake(socket, output, fake, data, length, config)
            }
            BypassStrategy.TCP_ACK_SKEW -> {
                // Sending a small packet with some data then the rest
                output.write(data, 0, 1); output.flush()
                delay(1)
                output.write(data, 1, length - 1); output.flush()
            }
            BypassStrategy.HTTP_METHOD_CASE_MANGLE -> {
                if (isProbableHttp(data, length)) {
                    val mod = FakePacketHelper.mangleHttpMethod(data, length)
                    output.write(mod); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_ZERO_WINDOW_DESYNC -> {
                try {
                    val originalSize = socket.receiveBufferSize
                    socket.receiveBufferSize = 0 // Simulate zero window
                    output.write(data, 0, 1); output.flush()
                    delay(config.delay1)
                    socket.receiveBufferSize = originalSize
                    output.write(data, 1, length - 1); output.flush()
                } catch (e: Throwable) {
                    output.write(data, 0, length); output.flush()
                }
            }
            BypassStrategy.TCP_OOB_DESYNC -> {
                try {
                    // 1. Part 1 (Real)
                    val split = 1
                    output.write(data, 0, split); output.flush()
                    
                    // 2. Desync OOB Byte (Urgent Pointer)
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                    
                    // 3. Junk overlap (Low TTL)
                    TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
                    output.write(FakePacketHelper.buildTlsNoise(rnd.nextInt(16, 32))); output.flush()
                    
                    // 4. Part 2 (Real)
                    delay(config.delay1)
                    TtlHelper.setTtl(socket, 64)
                    output.write(data, split, length - split); output.flush()
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.BYEBYEDPI_SIM -> {
                try {
                    val sniOffset = TlsParser.findSniOffset(data, length, host)
                    if (sniOffset != -1) {
                        // 1. Ghost Packet (Low TTL)
                        TtlHelper.setTtl(socket, 3)
                        output.write(FakePacketHelper.buildChromeHello(host)); output.flush()
                        delay(2)
                        
                        // 2. Real data fragmented with OOB
                        TtlHelper.setTtl(socket, 64)
                        val split = sniOffset + 1
                        output.write(data, 0, split); output.flush()
                        try { socket.sendUrgentData(0xFF) } catch (e: Throwable) {}
                        delay(config.delay1)
                        output.write(data, split, length - split); output.flush()
                    } else {
                        val split = (length / 2).coerceIn(1, length - 1)
                        output.write(data, 0, split); output.flush()
                        delay(config.delay1)
                        output.write(data, split, length - split); output.flush()
                    }
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_DATA_DESYNC -> {
                try {
                    val split = (length / 2).coerceIn(1, length - 1)
                    // 1. Fake overlapping data with low TTL
                    TtlHelper.setTtl(socket, rnd.nextInt(2, 4))
                    output.write(FakePacketHelper.buildUdpNoise(split + 8)); output.flush()
                    delay(1)
                    
                    // 2. OOB Byte to confuse state machine
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                    
                    // 3. Real data fragmented
                    TtlHelper.setTtl(socket, 64)
                    output.write(data, 0, split); output.flush()
                    delay(config.delay1)
                    output.write(data, split, length - split); output.flush()
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_ACK_SKEW_ADVANCED -> {
                output.write(data, 0, 1); output.flush()
                delay(rnd.nextLong(5, 20))
                if (length > 1) {
                    val s2 = (length - 1) / 2
                    output.write(data, 1, s2); output.flush()
                    delay(rnd.nextLong(2, 10))
                    output.write(data, 1 + s2, length - 1 - s2); output.flush()
                }
            }
            BypassStrategy.TCP_FOOL_DPI -> {
                try {
                    // Send a segment that looks like a middle-connection packet but with low TTL
                    TtlHelper.setTtl(socket, 2)
                    output.write(FakePacketHelper.buildTlsNoise(32)); output.flush()
                    delay(1)
                    TtlHelper.setTtl(socket, 64)
                    output.write(data, 0, length); output.flush()
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.BYEBYEDPI_HYBRID -> {
                try {
                    val sniOffset = TlsParser.findSniOffset(data, length, host)
                    if (sniOffset != -1) {
                        // 1. Ghost Session Preamble
                        TtlHelper.setTtl(socket, 2)
                        output.write(FakePacketHelper.buildTlsNoise(32)); output.flush()
                        delay(2)
                        
                        // 2. Real data with window shaking and OOB
                        TtlHelper.setTtl(socket, 64)
                        val split1 = sniOffset + 1
                        val split2 = sniOffset + (if (host.isNotEmpty()) host.length / 2 else 5)
                        
                        // Shake window
                        try { socket.receiveBufferSize = rnd.nextInt(512, 1024) } catch (e: Throwable) {}
                        
                        output.write(data, 0, split1); output.flush()
                        try { socket.sendUrgentData(0x00) } catch (e: Throwable) {}
                        delay(config.delay1)
                        
                        // Fake overlapping part
                        TtlHelper.setTtl(socket, 4)
                        output.write(FakePacketHelper.buildUdpNoise(split2 - split1 + 1)); output.flush()
                        delay(1)
                        
                        TtlHelper.setTtl(socket, 64)
                        output.write(data, split1, length - split1); output.flush()
                    } else {
                        val split = (length / 2).coerceIn(1, length - 1)
                        output.write(data, 0, split); output.flush()
                        delay(config.delay1)
                        output.write(data, split, length - split); output.flush()
                    }
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_REVERSE_FRAG -> {
                try {
                    if (length > 10) {
                        val split = length / 2
                        val p1 = data.copyOfRange(0, split)
                        val p2 = data.copyOfRange(split, length)
                        
                        // Send part 2 first
                        output.write(p2); output.flush()
                        delay(rnd.nextLong(1, 5))
                        output.write(p1); output.flush()
                    } else {
                        output.write(data, 0, length); output.flush()
                    }
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.DIRECT -> {
                output.write(data, 0, length); output.flush()
            }
            else -> {
                val split = 1; output.write(data, 0, split); output.flush(); delay(5)
                output.write(data, split, length - split); output.flush()
            }
        }
    }
}

