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

enum class BypassStrategy {
    DIRECT, FAKE_PACKET, SNI_SPLIT, SNI_TRIPLE, SNI_MANGLE, TLS_DIRTY, TLS_PAD, TLS_GREASE,
    TCP_OOB_DESYNC, OOB_DESYNC, GHOST_PACKETS, WINDOW_SIZE, TCP_ZERO_WINDOW,
    SLOW_SEND, FRAGMENT_MULTI, TLS_REC_SPLIT, TLS_MULTI_FRAG, CHAOS,
    TCP_MSS_CLAMP, TCP_URG_SKEW, TLS_EXT_SKEW, TCP_FAST_RETRANSMIT_SIM,
    TLS_REC_MANGLE, TCP_REORDER_SIM, TCP_FAST_OPEN_FAKE, TLS_PADDING_RAND,
    HTTP_HOST_SPACE, TLS_REHANDSHAKE_FAKE, HTTP_RANGE_SKEW, TCP_RST_FAKE,
    TLS_SNI_SKEW, HTTP_VERSION_SKEW, TCP_TIMESTAMP_MANGLE,
    TLS_CIPHER_SHUFFLE, HTTP_USER_AGENT_SKEW, TCP_URGENT_RANDOM, TLS_ALPN_SKEW,
    HTTP_AUTH_RANDOM, TCP_WINDOW_SIZE_CHAOS, TLS_EXTENSION_GREASE,
    HTTP_HEADER_FUZZING, TCP_REORDER_CHAOS, TLS_HELLO_JUNK,
    HTTP_METHOD_FAKE, TLS_LEGACY_HELLOS, TCP_KEEP_ALIVE_FAKE,
    HTTP_HOST_CASE_MANGLE, TLS_SESSION_TICKET_SKEW,
    TLS_MULTI_SNI, HTTP_CHUNKED_FAKE, TCP_WINDOW_RESTRICT, TLS_COMPRESSION_FAKE,
    TLS_ECH_FAKE, TCP_WINDOW_SCAN, HTTP_PIPELINE_FAKE,
    TLS_CHROME_HELLO_FAKE, TLS_FIREFOX_HELLO_FAKE, TLS_13_HELLO_FAKE, TCP_REORDER_DESYNC,
    TLS_SESSION_ID_RAND, TCP_ACK_DELAY, TLS_GREASE_SKEW
}

enum class NetworkType { WIFI, MOBILE, UNKNOWN }

enum class HostCategory { STREAMING, SOCIAL, MESSENGER, SEARCH, AI, FINANCE, CDN, NEWS, GAMING, SHOPPING, DEV, OTHER }

object ProxyStats {
    private val bufferPool8k = LinkedBlockingQueue<ByteArray>(256)
    private val bufferPool16k = LinkedBlockingQueue<ByteArray>(128)

    fun obtain8k(): ByteArray = bufferPool8k.poll() ?: ByteArray(8192)
    fun release8k(buf: ByteArray) { bufferPool8k.offer(buf) }
    fun obtain16k(): ByteArray = bufferPool16k.poll() ?: ByteArray(16384)
    fun release16k(buf: ByteArray) { bufferPool16k.offer(buf) }

    private val _bytesTransferred = MutableStateFlow(0L)
    val bytesTransferred: StateFlow<Long> = _bytesTransferred.asStateFlow()

    private val _activeConnections = MutableStateFlow(0)
    val activeConnections: StateFlow<Int> = _activeConnections.asStateFlow()

    private val _speedBytesPerSecond = MutableStateFlow(0L)
    val speedBytesPerSecond: StateFlow<Long> = _speedBytesPerSecond.asStateFlow()

    private val _speedHistory = MutableStateFlow(emptyList<Long>())
    val speedHistory: StateFlow<List<Long>> = _speedHistory.asStateFlow()

    private val _errors = MutableStateFlow(0L)
    val errors: StateFlow<Long> = _errors.asStateFlow()

    private val _censorshipIntensity = MutableStateFlow(0)
    val censorshipIntensity: StateFlow<Int> = _censorshipIntensity.asStateFlow()

    private val _recoveryLog = MutableStateFlow(emptyList<String>())
    val recoveryLog: StateFlow<List<String>> = _recoveryLog.asStateFlow()

    private val _trafficLog = MutableStateFlow(emptyList<String>())
    val trafficLog: StateFlow<List<String>> = _trafficLog.asStateFlow()

    private val _signalQuality = MutableStateFlow(100)
    val signalQuality: StateFlow<Int> = _signalQuality.asStateFlow()

    private val _topHosts = MutableStateFlow(emptyList<Pair<String, Int>>())
    val topHosts: StateFlow<List<Pair<String, Int>>> = _topHosts.asStateFlow()

    private val _pool8kSize = MutableStateFlow(0)
    val pool8kSize: StateFlow<Int> = _pool8kSize.asStateFlow()

    private val _pool16kSize = MutableStateFlow(0)
    val pool16kSize: StateFlow<Int> = _pool16kSize.asStateFlow()

    private val _congestionWindow = MutableStateFlow(10)
    val congestionWindow: StateFlow<Int> = _congestionWindow.asStateFlow()

    private val _dnsSuccessCount = MutableStateFlow(0L)
    val dnsSuccessCount: StateFlow<Long> = _dnsSuccessCount.asStateFlow()

    private val _dnsFailureCount = MutableStateFlow(0L)
    val dnsFailureCount: StateFlow<Long> = _dnsFailureCount.asStateFlow()

    private val _stabilityScore = MutableStateFlow(100)
    val stabilityScore: StateFlow<Int> = _stabilityScore.asStateFlow()

    private val _successRate = MutableStateFlow(100)
    val successRate: StateFlow<Int> = _successRate.asStateFlow()

    fun recordDnsResult(success: Boolean) {
        if (success) {
            _dnsSuccessCount.update { it + 1 }
            recordGlobalSuccess(0)
        } else {
            _dnsFailureCount.update { it + 1 }
            recordCensorshipEvent(true)
        }
    }

    fun forceRecovery(reason: String) {
        logRecovery("Force recovery: $reason")
        BypassConfig.rotateGlobalStrategy()
    }
    
    fun reset(clearLog: Boolean) {
        _bytesTransferred.value = 0
        _errors.value = 0
        _speedHistory.value = emptyList()
        _speedBytesPerSecond.value = 0
        _signalQuality.value = 100
        _topHosts.value = emptyList()
        _congestionWindow.value = 10
        _dnsSuccessCount.value = 0
        _dnsFailureCount.value = 0
        _stabilityScore.value = 100
        _successRate.value = 100
        if (clearLog) {
            _recoveryLog.value = emptyList()
            _trafficLog.value = emptyList()
        }
    }

    fun startSpeedMonitor(scope: CoroutineScope) {
        scope.launch {
            var lastBytes = _bytesTransferred.value
            while (isActive) {
                delay(1000)
                val currentBytes = _bytesTransferred.value
                val speed = (currentBytes - lastBytes).coerceAtLeast(0)
                _speedBytesPerSecond.value = speed
                
                _speedHistory.update { current ->
                    (listOf(speed) + current).take(60)
                }
                
                lastBytes = currentBytes
                
                _pool8kSize.value = bufferPool8k.size
                _pool16kSize.value = bufferPool16k.size
                
                // Adaptive signal quality based on success rate and intensity
                val quality = (successRate.value - censorshipIntensity.value / 2).coerceIn(0, 100)
                _signalQuality.value = quality
            }
        }
    }

    val currentJitterFactor: Double get() = if (censorshipIntensity.value > 50) 0.5 else 0.1

    fun formatBytes(bytes: Long): String {
        if (bytes < 1024) return "$bytes B"
        val exp = (Math.log(bytes.toDouble()) / Math.log(1024.0)).toInt()
        val pre = "KMGTPE"[exp - 1].toString()
        return String.format("%.1f %sB", bytes / Math.pow(1024.0, exp.toDouble()), pre)
    }

    fun recordGlobalSuccess(rtt: Long) {
        if (rtt > 0) {
             _stabilityScore.update { (it * 0.95 + 100 * 0.05).toInt().coerceIn(0, 100) }
        }
        _successRate.update { (it * 0.98 + 100 * 0.02).toInt().coerceIn(0, 100) }
    }

    fun recordCensorshipEvent(isBlocked: Boolean) {
        if (isBlocked) {
            _errors.update { it + 1 }
            _successRate.update { (it * 0.9 + 0 * 0.1).toInt().coerceIn(0, 100) }
            _censorshipIntensity.update { (it + 5).coerceAtMost(100) }
        } else {
            _censorshipIntensity.update { (it - 1).coerceAtLeast(0) }
        }
    }

    fun logRecovery(msg: String) {
        _recoveryLog.update { current ->
            (listOf("[${java.text.SimpleDateFormat("HH:mm:ss", Locale.ROOT).format(Date())}] $msg") + current).take(100)
        }
    }

    fun addTraffic(host: String) {
        _trafficLog.update { current ->
            (listOf(host) + current).take(50)
        }
        
        _topHosts.update { current ->
            val hosts = current.toMutableList()
            val idx = hosts.indexOfFirst { it.first == host }
            if (idx != -1) {
                hosts[idx] = host to hosts[idx].second + 1
            } else {
                hosts.add(host to 1)
            }
            hosts.sortedByDescending { it.second }.take(10)
        }
    }

    fun updateBytes(delta: Long) {
        _bytesTransferred.update { it + delta }
    }

    fun updateConnections(delta: Int) {
        _activeConnections.update { it + delta }
    }

    fun updateCongestionWindow(delta: Int) {
        _congestionWindow.update { (it + delta).coerceIn(2, 128) }
    }
    
    fun getSuccessRate() = _successRate.value
}

object HostClassifier {
    fun classify(host: String): HostCategory {
        val h = host.lowercase()
        return when {
            h.contains("youtube") || h.contains("netflix") || h.contains("twitch") -> HostCategory.STREAMING
            h.contains("facebook") || h.contains("instagram") || h.contains("twitter") || h.contains("tiktok") -> HostCategory.SOCIAL
            h.contains("whatsapp") || h.contains("telegram") || h.contains("discord") -> HostCategory.MESSENGER
            h.contains("google") || h.contains("bing") || h.contains("duckduckgo") -> HostCategory.SEARCH
            h.contains("openai") || h.contains("anthropic") || h.contains("mistral") -> HostCategory.AI
            h.contains("bank") || h.contains("crypto") || h.contains("binance") -> HostCategory.FINANCE
            h.contains("github") || h.contains("gitlab") || h.contains("npm") || h.contains("docker") -> HostCategory.DEV
            else -> HostCategory.OTHER
        }
    }
}

data class SessionConfig(val strategy: BypassStrategy, val frag1: Int, val frag2: Int, val frag3: Int, val delay1: Long, val delay2: Long, val fakeTtl: Int)

data class StrategyMetric(val strategy: BypassStrategy, val score: Int, val successes: Long, val failures: Long, val avgRtt: Long)

enum class StrategyGroup { LIGHT, MEDIUM, HEAVY, EXTREME }

object BypassConfig {
    private val _strategy = MutableStateFlow(BypassStrategy.SNI_SPLIT)
    val strategy: StateFlow<BypassStrategy> = _strategy.asStateFlow()
    
    private val _censorshipLevel = MutableStateFlow(0) // 0-100
    val censorshipLevel: StateFlow<Int> = _censorshipLevel.asStateFlow()

    private val strategyGrouping = mapOf(
        StrategyGroup.LIGHT to listOf(BypassStrategy.SNI_SPLIT, BypassStrategy.TLS_DIRTY, BypassStrategy.TLS_PAD, BypassStrategy.HTTP_HOST_SPACE, BypassStrategy.TLS_SESSION_ID_RAND),
        StrategyGroup.MEDIUM to listOf(BypassStrategy.SNI_TRIPLE, BypassStrategy.TLS_GREASE, BypassStrategy.FRAGMENT_MULTI, BypassStrategy.TLS_REC_SPLIT, BypassStrategy.TLS_SNI_SKEW, BypassStrategy.TLS_GREASE_SKEW),
        StrategyGroup.HEAVY to listOf(BypassStrategy.OOB_DESYNC, BypassStrategy.GHOST_PACKETS, BypassStrategy.TLS_MULTI_FRAG, BypassStrategy.TLS_CHROME_HELLO_FAKE, BypassStrategy.TLS_ECH_FAKE, BypassStrategy.TLS_FIREFOX_HELLO_FAKE, BypassStrategy.TLS_13_HELLO_FAKE, BypassStrategy.TCP_ACK_DELAY),
        StrategyGroup.EXTREME to listOf(BypassStrategy.CHAOS, BypassStrategy.TLS_MULTI_SNI, BypassStrategy.TCP_WINDOW_SCAN, BypassStrategy.TCP_ZERO_WINDOW, BypassStrategy.TCP_REORDER_DESYNC)
    )

    private val _currentNetworkType = MutableStateFlow(NetworkType.UNKNOWN)
    val currentNetworkType: StateFlow<NetworkType> = _currentNetworkType.asStateFlow()

    private val strategyScores = ConcurrentHashMap<HostCategory, ConcurrentHashMap<BypassStrategy, AtomicInteger>>()
    private val hostStrategyMemory = ConcurrentHashMap<String, BypassStrategy>()
    private val hostBlacklist = ConcurrentHashMap<String, MutableMap<BypassStrategy, Long>>()
    private val strategyStats = ConcurrentHashMap<BypassStrategy, Triple<Long, Long, Long>>() // Successes, Failures, Total RTT

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

    var isAutoTuning = true
    var frag1 = 1
    var frag2 = 5
    var frag3 = 2
    var delay1 = 20L
    var delay2 = 100L
    var fakeTtl = 3
    var isDiagnosticMode = false
    var blockQuic = true
    var isPanicMode = false
    var isCharging = true

    init {
        HostCategory.entries.forEach { cat ->
            val catMap = ConcurrentHashMap<BypassStrategy, AtomicInteger>()
            BypassStrategy.entries.forEach { 
                catMap[it] = AtomicInteger(100)
            }
            strategyScores[cat] = catMap
        }
        BypassStrategy.entries.forEach {
            strategyStats[it] = Triple(0L, 0L, 0L)
        }
    }

    fun loadTuningSettings(context: Context) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
        isAutoTuning = prefs.getBoolean("is_auto_tuning", true)
        blockQuic = prefs.getBoolean("block_quic", true)
        isDiagnosticMode = prefs.getBoolean("is_diagnostic_mode", false)
        val savedStrat = prefs.getString("global_strategy", BypassStrategy.SNI_SPLIT.name)
        try {
            _strategy.value = BypassStrategy.valueOf(savedStrat!!)
        } catch (e: Exception) {
            _strategy.value = BypassStrategy.SNI_SPLIT
        }
        
        val scorePrefs = context.getSharedPreferences("pink_proxy_scores", Context.MODE_PRIVATE)
        BypassStrategy.entries.forEach { strat ->
            val score = scorePrefs.getInt("score_${strat.name}", 100)
            strategyScores[HostCategory.OTHER]?.get(strat)?.set(score)
        }
    }

    fun saveTuningSettings(context: Context) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
        prefs.edit().apply {
            putBoolean("is_auto_tuning", isAutoTuning)
            putBoolean("block_quic", blockQuic)
            putBoolean("is_diagnostic_mode", isDiagnosticMode)
            putString("global_strategy", _strategy.value.name)
            apply()
        }
        saveScores(context)
    }

    fun saveScores(context: Context) {
        val prefs = context.getSharedPreferences("pink_proxy_scores", Context.MODE_PRIVATE)
        prefs.edit().apply {
            strategyScores[HostCategory.OTHER]?.forEach { (strat, score) ->
                putInt("score_${strat.name}", score.get())
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
        
        hostStrategyMemory[host]?.let { remembered ->
            if (blacklisted?.get(remembered)?.let { now < it } == true) {
                hostStrategyMemory.remove(host)
            } else if ((scores[remembered]?.get() ?: 0) > 40) {
                return remembered
            }
        }

        val entries = scores.entries.toList()
        val validEntries = entries.filter { entry ->
            val blacklistedUntil = blacklisted?.get(entry.key) ?: 0L
            now >= blacklistedUntil
        }
        
        if (validEntries.isEmpty()) return BypassStrategy.CHAOS

        // Weighting by score AND strategy group relevance to censorship level
        val weightedEntries = validEntries.map { entry ->
            var weight = entry.value.get().coerceAtLeast(1).toDouble()
            val group = strategyGrouping.entries.find { it.value.contains(entry.key) }?.key
            if (group == preferredGroup) weight *= 2.5
            else if (group == StrategyGroup.EXTREME && level < 30) weight *= 0.2 // Don't over-engineer simple cases
            
            entry.key to weight
        }

        val totalWeight = weightedEntries.sumOf { it.second }
        var random = ThreadLocalRandom.current().nextDouble(totalWeight)
        for (entry in weightedEntries) {
            random -= entry.second
            if (random <= 0) return entry.first
        }
        return weightedEntries.maxByOrNull { it.second }?.first ?: BypassStrategy.SNI_SPLIT
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
                        hostStrategyMemory.clear() // Force re-evaluation of some hosts
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
            hostStrategyMemory[it] = strat 
            hostBlacklist[it]?.remove(strat)
        }
        
        strategyStats[strat]?.let { (s, f, t) ->
            strategyStats[strat] = Triple(s + 1, f, t + rtt)
        }
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
            if (hostStrategyMemory[it] == strat) hostStrategyMemory.remove(it)
            
            val blacklist = hostBlacklist.getOrPut(it) { ConcurrentHashMap() }
            blacklist[strat] = System.currentTimeMillis() + 600000 // 10 min
        }
        
        strategyStats[strat]?.let { (s, f, t) ->
            strategyStats[strat] = Triple(s, f + 1, t)
        }
    }

    fun recordFailure(strat: BypassStrategy, isCritical: Boolean, context: Context?) = recordFailure(strat, null as String?)

    fun performSelfHealing() {
        val rate = ProxyStats.getSuccessRate()
        if (rate < 40 && !isPanicMode) {
            panicOptimize()
        } else if (rate > 85 && isPanicMode) {
            isPanicMode = false
            _isPanicModeFlow.value = false
            ProxyStats.logRecovery("Stability restored: $rate%. Normal mode.")
        }
    }

    fun panicOptimize() {
        isPanicMode = true
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

    fun testInitialStrategies(context: Context) {
        CoroutineScope(Dispatchers.IO).launch {
            val testHosts = listOf("www.google.com", "cloudflare.com")
            for (host in testHosts) {
                for (strat in listOf(BypassStrategy.SNI_SPLIT, BypassStrategy.TLS_DIRTY, BypassStrategy.FRAGMENT_MULTI)) {
                    try {
                        val start = System.currentTimeMillis()
                        val socket = java.net.Socket()
                        socket.soTimeout = 3000
                        socket.connect(java.net.InetSocketAddress(host, 443), 3000)
                        
                        val hello = FakePacketHelper.buildFakeClientHello(host)
                        val out = socket.getOutputStream()
                        
                        // Apply basic strategy behavior
                        if (strat == BypassStrategy.SNI_SPLIT) {
                            val split = hello.size / 2
                            out.write(hello, 0, split)
                            out.flush()
                            delay(5)
                            out.write(hello, split, hello.size - split)
                            out.flush()
                        } else {
                            out.write(hello)
                            out.flush()
                        }
                        
                        val input = socket.getInputStream()
                        val resp = input.read()
                        val rtt = System.currentTimeMillis() - start
                        
                        if (resp != -1) {
                            recordSuccess(strat, rtt, host)
                        } else {
                            recordFailure(strat, host)
                        }
                        socket.close()
                    } catch (e: Exception) {
                        recordFailure(strat, host)
                    }
                }
            }
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

    fun recordStrategyResult(host: String, strategy: BypassStrategy, success: Boolean) {
        if (success) {
            recordSuccess(strategy, 50, host)
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
            val (s, f, t) = strategyStats[strat] ?: Triple(0L, 0L, 0L)
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
            if (errorCounter > 5) {
                ProxyStats.updateCongestionWindow(-5)
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
        } catch (e: Exception) {}

        when (strategy) {
            BypassStrategy.SNI_SPLIT -> {
                val offset = TlsParser.findSniOffset(data, length, host)
                val split = if (offset != -1) offset + 1 else config.frag1.coerceIn(1, length - 1)
                val safeSplit = split.coerceIn(1, length - 1)
                output.write(data, 0, safeSplit); output.flush(); delay(config.delay1)
                output.write(data, safeSplit, length - safeSplit); output.flush()
            }
            BypassStrategy.SNI_TRIPLE -> {
                val offset = TlsParser.findSniOffset(data, length, host)
                val (s1, s2) = if (offset != -1) {
                    val part = (host.length / 3).coerceAtLeast(1)
                    (offset + part) to (offset + 2 * part)
                } else {
                    val split1 = config.frag1.coerceIn(1, (length - 2).coerceAtLeast(1))
                    val split2 = (split1 + config.frag2).coerceIn(split1 + 1, (length - 1).coerceAtLeast(split1 + 1))
                    split1 to split2
                }
                val safeS1 = s1.coerceIn(1, (length - 2).coerceAtLeast(1))
                val safeS2 = s2.coerceIn(safeS1 + 1, (length - 1).coerceAtLeast(safeS1 + 1))
                output.write(data, 0, safeS1); output.flush(); delay(config.delay1)
                output.write(data, safeS1, safeS2 - safeS1); output.flush(); delay(config.delay2)
                output.write(data, safeS2, length - safeS2); output.flush()
            }
            BypassStrategy.FAKE_PACKET -> {
                val fake = FakePacketHelper.buildFakeClientHello(host, rnd.nextInt(40, 91))
                TtlHelper.setTtl(socket, config.fakeTtl); output.write(fake); output.flush()
                delay(config.delay1); TtlHelper.setTtl(socket, 64); output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TCP_OOB_DESYNC -> {
                try { socket.sendUrgentData(0xFF) } catch (e: Exception) {}
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
                try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Exception) {}
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
                try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Exception) {}
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
                try { socket.sendUrgentData(rnd.nextInt(1, 255)) } catch (e: Exception) {}
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
                    output.write(data, split, length - split); output.flush(); delay(config.delay1)
                    output.write(data, 0, split); output.flush()
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

class PinkProxyServer(private val vpnService: VpnService, private val port: Int) {
    private var proxyDispatcher: ExecutorCoroutineDispatcher? = null
    private var serverJob: Job? = null
    private var serverSocket: ServerSocket? = null
    
    fun start() {
        if (serverJob?.isActive == true) return
        
        val dispatcher = Executors.newCachedThreadPool().asCoroutineDispatcher()
        proxyDispatcher = dispatcher
        val parentJob = SupervisorJob()
        val scope = CoroutineScope(dispatcher + parentJob)
        serverJob = parentJob
        
        ProxyStats.startSpeedMonitor(scope)
        BypassConfig.startAutonomousOptimizer(scope)
        
        scope.launch {
            try {
                serverSocket = ServerSocket().apply {
                    reuseAddress = true
                    bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port))
                }
                ProxyStats.logRecovery("Proxy server started on port $port")
                while (isActive) {
                    val client = try {
                        serverSocket?.accept()
                    } catch (e: SocketException) {
                        null
                    } ?: break
                    
                    launch { handleClient(client) }
                }
            } catch (e: Exception) {
                if (isActive) Log.e("PinkProxy", "Server error", e)
            } finally {
                try { serverSocket?.close() } catch (e: Exception) {}
                serverSocket = null
            }
        }
    }

    fun stop() {
        serverJob?.cancel()
        try { serverSocket?.close() } catch (e: Exception) {}
        serverSocket = null
        proxyDispatcher?.close()
        proxyDispatcher = null
    }

    private suspend fun readExactly(input: InputStream, buffer: ByteArray, offset: Int, length: Int) {
        var read = 0
        while (read < length) {
            val r = input.read(buffer, offset + read, length - read)
            if (r == -1) throw IOException("EOF")
            read += r
        }
    }

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    private suspend fun handleClient(client: Socket) {
        ProxyStats.updateConnections(1)
        var targetSocket: Socket? = null
        try {
            client.soTimeout = 15000
            val input = client.getInputStream()
            val output = client.getOutputStream()

            // SOCKS5 Handshake
            val handshakeHeader = ByteArray(2)
            readExactly(input, handshakeHeader, 0, 2)
            if (handshakeHeader[0].toInt() != 5) {
                client.close()
                return
            }
            val numMethods = handshakeHeader[1].toInt() and 0xFF
            val methods = ByteArray(numMethods)
            readExactly(input, methods, 0, numMethods)
            output.write(byteArrayOf(5, 0)) // No authentication
            output.flush()

            // Command request
            val requestHeader = ByteArray(4)
            readExactly(input, requestHeader, 0, 4)
            val ver2 = requestHeader[0].toInt()
            val cmd = requestHeader[1].toInt()
            val atyp = requestHeader[3].toInt()

            if (ver2 != 5 || (cmd != 1 && cmd != 3)) { // Only CONNECT and UDP ASSOCIATE supported
                client.close()
                return
            }
            
            if (cmd == 3) { // UDP ASSOCIATE
                val atypUdp = atyp
                val addrBytesUdp = when (atypUdp) {
                    1 -> { val b = ByteArray(4); readExactly(input, b, 0, 4); b }
                    3 -> { val len = input.read(); val b = ByteArray(len); readExactly(input, b, 0, len); b }
                    4 -> { val b = ByteArray(16); readExactly(input, b, 0, 16); b }
                    else -> { client.close(); return }
                }
                val portUdpBytes = ByteArray(2)
                readExactly(input, portUdpBytes, 0, 2)
                
                // Open DatagramSocket to receive SOCKS5 UDP packets
                val udpSocket = java.net.DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
                val localPort = udpSocket.localPort
                
                // One outgoing socket for the entire UDP associate session
                val outSocket = java.net.DatagramSocket()
                try { vpnService.protect(outSocket) } catch (e: Exception) {}

                // Send Success response with our UDP bound address
                val resp = ByteArray(10)
                resp[0] = 5; resp[1] = 0; resp[2] = 0; resp[3] = 1
                resp[4] = 127; resp[5] = 0; resp[6] = 0; resp[7] = 1
                resp[8] = (localPort shr 8).toByte()
                resp[9] = localPort.toByte()
                output.write(resp)
                output.flush()
                
                var clientUdpAddress: InetAddress? = null
                var clientUdpPort = 0
                
                coroutineScope {
                    // Receive from Target, forward to SOCKS5 Client
                    launch(Dispatchers.IO) {
                        try {
                            val buffer = ByteArray(65535)
                            while (isActive) {
                                val packet = java.net.DatagramPacket(buffer, buffer.size)
                                outSocket.receive(packet)
                                if (clientUdpAddress != null) {
                                    val outBuffer = java.io.ByteArrayOutputStream()
                                    outBuffer.write(0) // RSV
                                    outBuffer.write(0) // RSV
                                    outBuffer.write(0) // FRAG
                                    
                                    val addrBytes = packet.address.address
                                    if (addrBytes.size == 4) {
                                        outBuffer.write(1)
                                        outBuffer.write(addrBytes)
                                    } else {
                                        outBuffer.write(4)
                                        outBuffer.write(addrBytes)
                                    }
                                    outBuffer.write(packet.port shr 8)
                                    outBuffer.write(packet.port and 0xFF)
                                    outBuffer.write(packet.data, packet.offset, packet.length)
                                    
                                    val respBytes = outBuffer.toByteArray()
                                    udpSocket.send(java.net.DatagramPacket(respBytes, respBytes.size, clientUdpAddress, clientUdpPort))
                                }
                            }
                        } catch (e: Exception) {
                            // Ignored
                        }
                    }

                    // Receive from SOCKS5 Client, forward to Target
                    launch(Dispatchers.IO) {
                        try {
                            val buffer = ByteArray(65535)
                            while (isActive) {
                                val packet = java.net.DatagramPacket(buffer, buffer.size)
                                udpSocket.receive(packet)
                                clientUdpAddress = packet.address
                                clientUdpPort = packet.port
                                
                                val data = packet.data
                                val len = packet.length
                                if (len < 10) continue
                                
                                // Parse SOCKS5 UDP header
                                val frag = data[2].toInt()
                                if (frag != 0) continue // Fragmented UDP not supported
                                
                                val pAtyp = data[3].toInt()
                                var headerLen = 4
                                var targetHost = ""
                                when (pAtyp) {
                                    1 -> {
                                        headerLen += 4
                                        val ipBytes = data.copyOfRange(4, 8)
                                        targetHost = InetAddress.getByAddress(ipBytes).hostAddress ?: ""
                                    }
                                    3 -> {
                                        val dlen = data[4].toInt() and 0xFF
                                        headerLen += 1 + dlen
                                        targetHost = String(data, 5, dlen)
                                    }
                                    4 -> {
                                        headerLen += 16
                                        val ipBytes = data.copyOfRange(4, 20)
                                        targetHost = InetAddress.getByAddress(ipBytes).hostAddress ?: ""
                                    }
                                }
                                val targetPortNum = ((data[headerLen].toInt() and 0xFF) shl 8) or (data[headerLen + 1].toInt() and 0xFF)
                                headerLen += 2
                                
                                val payload = data.copyOfRange(headerLen, len)
                                
                                if (targetPortNum == 53) {
                                    // Handle DNS query locally
                                    val query = DnsUtils.parseDnsQName(payload)
                                    if (query != null) {
                                        val resolvedIps = RobustResolver.resolve(query.qname, vpnService)
                                        if (resolvedIps.isNotEmpty()) {
                                            val ipStrs = resolvedIps.map { it.hostAddress ?: "" }.filter { it.isNotEmpty() }
                                            if (ipStrs.isNotEmpty()) {
                                                val dnsReply = DnsUtils.buildDnsReply(payload, ipStrs, query.qtype == 28)
                                                
                                                val outBuffer = java.io.ByteArrayOutputStream()
                                                outBuffer.write(0); outBuffer.write(0); outBuffer.write(0)
                                                outBuffer.write(pAtyp)
                                                if (pAtyp == 1) outBuffer.write(data, 4, 4)
                                                else if (pAtyp == 3) { outBuffer.write(data[4].toInt()); outBuffer.write(data, 5, data[4].toInt() and 0xFF) }
                                                else if (pAtyp == 4) outBuffer.write(data, 4, 16)
                                                outBuffer.write(targetPortNum shr 8); outBuffer.write(targetPortNum and 0xFF)
                                                outBuffer.write(dnsReply)
                                                
                                                val responseBytes = outBuffer.toByteArray()
                                                udpSocket.send(java.net.DatagramPacket(responseBytes, responseBytes.size, packet.address, packet.port))
                                            }
                                        }
                                    }
                                } else {
                                    // General UDP Forwarding - using shared resolver and avoiding per-packet coroutine where possible
                                    var targetIpStr = targetHost
                                    val resolved = RobustResolver.getCached(targetHost)
                                    if (resolved != null && resolved.isNotEmpty()) {
                                        targetIpStr = resolved.first().hostAddress ?: targetHost
                                    }
                                    
                                    try {
                                        val targetInet = InetAddress.getByName(targetIpStr)
                                        val outPacket = java.net.DatagramPacket(payload, payload.size, targetInet, targetPortNum)
                                        
                                        val strategy = BypassConfig.strategy.value
                                        
                                        if (BypassConfig.blockQuic && targetPortNum == 443 && payload.isNotEmpty() && (payload[0].toInt() and 0xC0) == 0xC0) {
                                            // Block QUIC traffic to force fallback to TCP
                                            continue
                                        }
                                        
                                        if (strategy != BypassStrategy.DIRECT) {
                                            if (targetPortNum == 443 && payload.isNotEmpty() && (payload[0].toInt() and 0xC0) == 0xC0) {
                                                // QUIC traffic detected - send a fake QUIC Initial packet with low TTL
                                                val fakeQuic = FakePacketHelper.buildQuicInitial()
                                                val fakeQuicPacket = java.net.DatagramPacket(fakeQuic, fakeQuic.size, targetInet, targetPortNum)
                                                TtlHelper.setUdpTtl(outSocket, 5)
                                                outSocket.send(fakeQuicPacket)
                                                delay(5)
                                                TtlHelper.setUdpTtl(outSocket, 64)
                                                outSocket.send(outPacket)
                                            } else if (targetPortNum == 53) {
                                                // DNS over UDP - send a Fake QUIC packet first to confuse DPI, then send actual DNS
                                                val quicSim = FakePacketHelper.buildQuicInitial()
                                                val quicPacket = java.net.DatagramPacket(quicSim, quicSim.size, targetInet, targetPortNum)
                                                TtlHelper.setUdpTtl(outSocket, 5)
                                                outSocket.send(quicPacket)
                                                delay(5)
                                                TtlHelper.setUdpTtl(outSocket, 64)
                                                outSocket.send(outPacket)
                                            } else {
                                                // General UDP Obfuscation - prepend noise packet with low TTL
                                                val noise = FakePacketHelper.buildFakeUdpPacket(java.util.concurrent.ThreadLocalRandom.current().nextInt(50, 150))
                                                val noisePacket = java.net.DatagramPacket(noise, noise.size, targetInet, targetPortNum)
                                                TtlHelper.setUdpTtl(outSocket, 5)
                                                outSocket.send(noisePacket)
                                                delay(2)
                                                TtlHelper.setUdpTtl(outSocket, 64)
                                                outSocket.send(outPacket)
                                            }
                                        } else {
                                            outSocket.send(outPacket)
                                        }
                                    } catch (e: Exception) {
                                        // If IP resolution failed or was not in cache, we might need a coroutine for this specific packet
                                        if (resolved == null) {
                                            launch(Dispatchers.IO) {
                                                try {
                                                    val res = RobustResolver.resolve(targetHost, vpnService)
                                                    if (res.isNotEmpty()) {
                                                        val targetInet = res.first()
                                                        val outPacket = java.net.DatagramPacket(payload, payload.size, targetInet, targetPortNum)
                                                        outSocket.send(outPacket)
                                                    }
                                                } catch (e2: Exception) {}
                                            }
                                        }
                                    }
                                }
                            }
                        } catch (e: Exception) {
                            // Ignored
                        } finally {
                            try { udpSocket.close() } catch (e: Exception) {}
                        }
                    }
                    
                    // Keep TCP connection alive, if it closes, UDP associate terminates
                    try {
                        input.read() // block until client closes
                    } finally {
                        udpSocket.close()
                        outSocket.close()
                        client.close()
                    }
                }
                return
            }
            val host = when (atyp) {
                1 -> { // IPv4
                    val addr = ByteArray(4)
                    readExactly(input, addr, 0, 4)
                    InetAddress.getByAddress(addr).hostAddress
                }
                3 -> { // Domain name
                    val len = input.read()
                    if (len == -1) throw IOException("EOF")
                    val addr = ByteArray(len)
                    readExactly(input, addr, 0, len)
                    String(addr)
                }
                4 -> { // IPv6
                    val addr = ByteArray(16)
                    readExactly(input, addr, 0, 16)
                    InetAddress.getByAddress(addr).hostAddress
                }
                else -> {
                    client.close()
                    return
                }
            }
            val portBytes = ByteArray(2)
            readExactly(input, portBytes, 0, 2)
            val targetPort = ((portBytes[0].toInt() and 0xff) shl 8) or (portBytes[1].toInt() and 0xff)
            
            // DNS Resolution with fallback
            val ips = try {
                RobustResolver.resolve(host, vpnService)
            } catch (e: Exception) {
                emptyList<InetAddress>()
            }
            
            if (ips.isEmpty()) {
                output.write(byteArrayOf(5, 4, 0, 1, 0, 0, 0, 0, 0, 0)) // Host unreachable
                output.flush()
                return
            }
            
            val targetIp = ips.first()
            ProxyStats.addTraffic(host)

            // Parallel connect racing for better reliability and speed
            targetSocket = try {
                withTimeout(15000) {
                    val deferreds = ips.take(3).map { ip ->
                        async(Dispatchers.IO) {
                            val s = Socket()
                            s.tcpNoDelay = true
                            s.keepAlive = true
                            vpnService.protect(s)
                            try {
                                s.connect(InetSocketAddress(ip, targetPort), 10000)
                                s
                            } catch (e: Exception) {
                                try { s.close() } catch (e2: Exception) {}
                                throw e
                            }
                        }
                    }
                    
                    val winner = kotlinx.coroutines.selects.select<Socket> {
                        deferreds.forEach { deferred ->
                            deferred.onAwait { it }
                        }
                    }
                    
                    // Cleanup other attempts
                    deferreds.forEach { def ->
                        if (def.isCompleted) {
                            val res = try { def.getCompleted() } catch (e: Exception) { null }
                            if (res != null && res !== winner) try { res.close() } catch (e: Exception) {}
                        } else {
                            def.cancel()
                        }
                    }
                    winner
                }
            } catch (e: Exception) {
                Log.e("PinkProxy", "Failed to connect to $host: ${e.message}")
                output.write(byteArrayOf(5, 1, 0, 1, 0, 0, 0, 0, 0, 0))
                output.flush()
                return
            }

            // Success response
            output.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            output.flush()
            
            client.soTimeout = 0 // Remove timeout for the tunneled connection
            targetSocket.soTimeout = 0

            // Tunneling with bypass
            val targetInput = targetSocket!!.getInputStream()
            val targetOutput = targetSocket!!.getOutputStream()

            val strategy = BypassConfig.getBestStrategyForHost(host)
            val config = BypassConfig.getSessionConfig(host, strategy, BypassConfig.currentRttMs.value)

            try {
                coroutineScope {
                    launch {
                        val buffer = ProxyStats.obtain16k()
                        var firstPacket = true
                        try {
                            var len = 0
                            while (isActive) {
                                len = input.read(buffer)
                                if (len == -1) break
                                
                                if (firstPacket) {
                                    try {
                                        BypassConfig.applyBypass(targetSocket!!, targetOutput, buffer, len, config, host)
                                    } catch (e: Exception) {
                                        BypassConfig.recordFailure(strategy, host)
                                        throw e
                                    }
                                    firstPacket = false
                                } else {
                                    targetOutput.write(buffer, 0, len)
                                    targetOutput.flush()
                                }
                                ProxyStats.updateBytes(len.toLong())
                            }
                        } catch (e: Exception) {
                            BypassConfig.TrafficShaper.recordError()
                            // Expected on socket close
                        } finally {
                            ProxyStats.release16k(buffer)
                            try { targetSocket?.shutdownOutput() } catch (e: Exception) {}
                            try { client.shutdownInput() } catch (e: Exception) {}
                        }
                    }

                    launch {
                        val buffer = ProxyStats.obtain16k()
                        var firstResponse = true
                        val startTime = System.currentTimeMillis()
                        try {
                            var len = 0
                            while (isActive) {
                                len = targetInput.read(buffer)
                                if (len == -1) break
                                
                                if (firstResponse) {
                                    BypassConfig.recordSuccess(strategy, System.currentTimeMillis() - startTime, host)
                                    firstResponse = false
                                }
                                
                                // Adaptive chunking based on congestion window
                                val cwnd = (ProxyStats.congestionWindow.value * 1024).coerceAtLeast(1024)
                                var sent = 0
                                while (sent < len) {
                                    val toSend = (len - sent).coerceAtMost(cwnd)
                                    output.write(buffer, sent, toSend)
                                    output.flush()
                                    sent += toSend
                                    if (sent < len) delay(1) 
                                }
                                
                                ProxyStats.updateBytes(len.toLong())
                            }
                        } catch (e: Exception) {
                            BypassConfig.TrafficShaper.recordError()
                            // Expected on socket close
                        } finally {
                            ProxyStats.release16k(buffer)
                            try { client.shutdownOutput() } catch (e: Exception) {}
                            try { targetSocket.shutdownInput() } catch (e: Exception) {}
                        }
                    }
                }
            } catch (e: Exception) {
                Log.v("PinkProxy", "Relay terminated for $host: ${e.message}")
            }
        } catch (e: Exception) {
            Log.v("PinkProxy", "Client handling error: ${e.message}")
        } finally {
            try { targetSocket?.close() } catch (e: Exception) {}
            try { client.close() } catch (e: Exception) {}
            ProxyStats.updateConnections(-1)
        }
    }
}
