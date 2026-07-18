package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.io.InputStream
import java.io.OutputStream
import java.net.ServerSocket
import java.net.Socket
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicInteger

object ProxyStats {
    private val _bytesTransferred = MutableStateFlow(0L)
    val bytesTransferred: StateFlow<Long> = _bytesTransferred.asStateFlow()
    
    private val _activeConnections = MutableStateFlow(0)
    val activeConnections: StateFlow<Int> = _activeConnections.asStateFlow()

    private val _speedBytesPerSecond = MutableStateFlow(0L)
    val speedBytesPerSecond: StateFlow<Long> = _speedBytesPerSecond.asStateFlow()

    private val _speedHistory = MutableStateFlow<List<Long>>(emptyList())
    val speedHistory: StateFlow<List<Long>> = _speedHistory.asStateFlow()

    private val _errors = MutableStateFlow(0L)
    val errors: StateFlow<Long> = _errors.asStateFlow()

    private val _successRate = MutableStateFlow(100)
    val successRate: StateFlow<Int> = _successRate.asStateFlow()

    private val _censorshipIntensity = MutableStateFlow(0)
    val censorshipIntensity: StateFlow<Int> = _censorshipIntensity.asStateFlow()

    private val _recoveryLog = MutableStateFlow<List<String>>(emptyList())
    val recoveryLog: StateFlow<List<String>> = _recoveryLog.asStateFlow()

    private val _trafficLog = MutableStateFlow<List<String>>(emptyList())
    val trafficLog: StateFlow<List<String>> = _trafficLog.asStateFlow()
    
    private val hostCounter = ConcurrentHashMap<String, AtomicLong>()
    private val _topHosts = MutableStateFlow<List<Pair<String, Long>>>(emptyList())
    val topHosts: StateFlow<List<Pair<String, Long>>> = _topHosts.asStateFlow()

    private val totalBytes = AtomicLong(0L)
    private val totalErrors = AtomicLong(0L)
    private val totalRequests = AtomicLong(0L)
    private val consecutiveErrors = AtomicLong(0L)
    
    private val slidingWindow = java.util.Collections.synchronizedList(mutableListOf<Boolean>())
    private val WINDOW_SIZE = 100

    private val censorshipWindow = java.util.Collections.synchronizedList(mutableListOf<Boolean>())
    private val CENSOR_WINDOW_SIZE = 40

    private val lastBytes = AtomicLong(0L)
    private val lastTime = AtomicLong(System.currentTimeMillis())
    
    init {
        kotlinx.coroutines.CoroutineScope(Dispatchers.Default).launch {
            while (true) {
                delay(5000)
                _topHosts.value = hostCounter.entries
                    .sortedByDescending { it.value.get() }
                    .take(10)
                    .map { it.key to it.value.get() }
            }
        }
    }

    private val _proxyHealthTrigger = kotlinx.coroutines.flow.MutableSharedFlow<String>(extraBufferCapacity = 1)
    val proxyHealthTrigger = _proxyHealthTrigger.asSharedFlow()

    fun addBytes(bytes: Long) {
        totalBytes.addAndGet(bytes)
        consecutiveErrors.set(0)
    }

    fun addError() {
        _errors.value = totalErrors.incrementAndGet()
        addToWindow(false)
        val current = consecutiveErrors.incrementAndGet()
        if (current >= 15) {
            _proxyHealthTrigger.tryEmit("High Consecutive Errors ($current)")
            consecutiveErrors.set(0)
        }
        
        // Auto-reset if overall quality is terrible
        if (totalRequests.get() > 50) {
            val rate = getSuccessRate()
            if (rate < 10) {
                BypassConfig.resetToDefaults()
                totalRequests.set(0)
                totalErrors.set(0)
                slidingWindow.clear()
                updateSuccessRate()
            }
        }
    }

    fun addRequest() {
        totalRequests.incrementAndGet()
    }

    fun recordGlobalSuccess() {
        consecutiveErrors.set(0)
        addToWindow(true)
    }

    private fun addToWindow(success: Boolean) {
        synchronized(slidingWindow) {
            slidingWindow.add(success)
            if (slidingWindow.size > WINDOW_SIZE) {
                slidingWindow.removeAt(0)
            }
        }
        updateSuccessRate()
    }

    private fun updateSuccessRate() {
        _successRate.value = getSuccessRate()
    }

    fun getActiveConnections() = _activeConnections.value

    fun getSuccessRate(): Int {
        val window = synchronized(slidingWindow) { slidingWindow.toList() }
        if (window.isEmpty()) {
            val req = totalRequests.get()
            if (req == 0L) return 100
            val err = totalErrors.get()
            return ((req - err).toFloat() / req.toFloat() * 100).toInt().coerceIn(0, 100)
        }
        val successCount = window.count { it }
        return (successCount.toFloat() / window.size.toFloat() * 100).toInt().coerceIn(0, 100)
    }

    fun addConnection() {
        _activeConnections.update { it + 1 }
    }

    fun removeConnection() {
        _activeConnections.update { if (it > 0) it - 1 else 0 }
    }

    fun forceRecovery(reason: String) {
        _proxyHealthTrigger.tryEmit(reason)
    }

    fun logRecovery(message: String) {
        val timestamp = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault()).format(java.util.Date())
        _recoveryLog.update { (listOf("[$timestamp] $message") + it).take(50) }
    }

    fun logTraffic(host: String, strategy: String? = null) {
        val timestamp = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault()).format(java.util.Date())
        val msg = if (strategy != null) "[$timestamp] $host via $strategy" else "[$timestamp] $host"
        _trafficLog.update { (listOf(msg) + it).take(30) }
        hostCounter.getOrPut(host) { AtomicLong(0L) }.incrementAndGet()
    }

    fun recordStrategySuccess(strategy: BypassStrategy, context: android.content.Context? = null) {
        BypassConfig.recordSuccess(strategy, context)
    }

    fun recordCensorshipEvent(interfered: Boolean) {
        synchronized(censorshipWindow) {
            censorshipWindow.add(interfered)
            if (censorshipWindow.size > CENSOR_WINDOW_SIZE) {
                censorshipWindow.removeAt(0)
            }
            val count = censorshipWindow.count { it }
            _censorshipIntensity.value = (count.toFloat() / censorshipWindow.size.toFloat() * 100).toInt().coerceIn(0, 100)
        }
    }

    fun autoCleanup() {
        _recoveryLog.update { it.take(20) }
    }
    
    fun reset(clearLog: Boolean = false) {
        totalBytes.set(0L)
        totalErrors.set(0L)
        consecutiveErrors.set(0)
        totalRequests.set(0L)
        _bytesTransferred.value = 0L
        _activeConnections.value = 0
        _speedBytesPerSecond.value = 0L
        _speedHistory.value = emptyList()
        _errors.value = 0L
        _censorshipIntensity.value = 0
        censorshipWindow.clear()
        if (clearLog) _recoveryLog.value = emptyList()
        lastBytes.set(0L)
        lastTime.set(System.currentTimeMillis())
    }

    fun updateSpeed() {
        val currentBytes = totalBytes.get()
        _bytesTransferred.value = currentBytes
        val currentTime = System.currentTimeMillis()
        val diffTime = currentTime - lastTime.get()
        if (diffTime >= 1000) {
            val bytesDiff = currentBytes - lastBytes.get()
            val speed = (bytesDiff * 1000) / diffTime
            _speedBytesPerSecond.value = speed
            _speedHistory.update { (it + speed).takeLast(60) }
            lastBytes.set(currentBytes)
            lastTime.set(currentTime)
            _topHosts.value = hostCounter.entries.sortedByDescending { it.value.get() }.take(10).map { Pair(it.key, it.value.get()) }
        }
    }

    fun formatBytes(bytes: Long): String {
        val kb = bytes / 1024.0
        val mb = kb / 1024.0
        val gb = mb / 1024.0
        return when {
            gb >= 1.0 -> String.format(java.util.Locale.US, "%.2f GB", gb)
            mb >= 1.0 -> String.format(java.util.Locale.US, "%.2f MB", mb)
            kb >= 1.0 -> String.format(java.util.Locale.US, "%.2f KB", kb)
            else -> "$bytes B"
        }
    }
}

enum class BypassStrategy {
    FAKE_PACKET,    // Fake packet injection
    SNI_SPLIT,      // Split exactly at SNI
    SNI_TRIPLE,     // Split SNI into 3 chunks
    SNI_MANGLE,     // Case-mangle SNI hostname
    TLS_DIRTY,      // Add junk between record header and handshake
    TLS_PAD,        // Pad TLS ClientHello with extra extensions
    TLS_GREASE,     // Inject GREASE extensions into ClientHello
    HOST_MIXED,     // Mixed-case Host header and methods
    FRAG_3_5,       // Random fragment size 3-5
    CHUNKY,         // Split into many 1-2 byte chunks
    HOST_CASE,      // Case-shift HTTP Host header
    RAND_SPLIT,     // Split at random position in ClientHello
    HEADER_SPLIT,   // Split TLS record header
    TCP_OOB_DESYNC, // Out-of-band data (fake packet equivalent) for DPI confusion
    HTTP_SPACE,     // HTTP method space/desync trick
    HTTP_TAB,       // HTTP method tab trick
    WINDOW_SIZE,    // TCP Window Size manipulation
    SLOW_SEND,      // Send initial data very slowly in tiny chunks
    OOB_DESYNC,     // TCP Out-of-band data injection
    TCP_ZERO_WINDOW,// Send data then signal zero window to force probes
    GHOST_PACKETS,  // Send tiny randomized encrypted-looking packets periodically
    DIRECT          // No bypass
}

enum class NetworkType {
    WIFI,
    MOBILE,
    UNKNOWN
}

enum class HostCategory {
    STREAMING,
    SOCIAL,
    MESSENGER,
    OTHER
}

object HostClassifier {
    fun classify(host: String): HostCategory {
        val lower = host.lowercase(java.util.Locale.ROOT)
        return when {
            // Streaming/Video
            lower.contains("youtube") || lower.contains("googlevideo") || lower.contains("ytimg") ||
            lower.contains("ggpht") || lower.contains("twitch") || lower.contains("netflix") ||
            lower.contains("vimeo") || lower.contains("dailymotion") || lower.contains("hulu") ||
            lower.contains("disney") || lower.contains("hbomax") || lower.contains("primevideo") ||
            lower.contains("tiktok") -> HostCategory.STREAMING

            // Social & Images
            lower.contains("instagram") || lower.contains("cdninstagram") || lower.contains("facebook") ||
            lower.contains("fbcdn") || lower.contains("twitter") || lower.contains("twimg") ||
            lower.contains("x.com") || lower.contains("pinterest") || lower.contains("reddit") ||
            lower.contains("snapchat") || lower.contains("tumblr") -> HostCategory.SOCIAL

            // Messengers
            lower.contains("telegram") || lower.contains("t.me") || lower.contains("discord") ||
            lower.contains("whatsapp") || lower.contains("viber") || lower.contains("signal") ||
            lower.contains("messenger") -> HostCategory.MESSENGER

            // Others
            else -> HostCategory.OTHER
        }
    }
}

class SessionConfig(
    val strategy: BypassStrategy,
    val frag1: Int,
    val frag2: Int,
    val frag3: Int,
    val delay1: Long,
    val delay2: Long,
    val fakeTtl: Int
)

object BypassConfig {
    private val _currentStrategy = MutableStateFlow(BypassStrategy.FAKE_PACKET)
    val strategy: StateFlow<BypassStrategy> = _currentStrategy.asStateFlow()

    @Volatile var frag1 = 3
    @Volatile var frag2 = 5
    @Volatile var frag3 = 2
    @Volatile var delay1 = 25L
    @Volatile var delay2 = 20L
    @Volatile var fakeTtl = 3
    @Volatile var isAutoTuning = true
    @Volatile var blockQuic = true

    data class HostDna(
        var frag1: Int,
        var frag2: Int,
        var delay1: Long,
        var strategy: BypassStrategy? = null,
        var lastSuccess: Long = 0L
    )
    private val hostDnas = ConcurrentHashMap<String, HostDna>()

    fun getDnaForHost(host: String): HostDna {
        return hostDnas.getOrPut(host) {
            HostDna(frag1, frag2, delay1)
        }
    }

    fun mutateDnaForHost(host: String) {
        val dna = getDnaForHost(host)
        dna.frag1 = (dna.frag1 + listOf(-1, 1).random()).coerceIn(1, 15)
        dna.frag2 = (dna.frag2 + listOf(-1, 1).random()).coerceIn(1, 20)
        dna.delay1 = (dna.delay1 + listOf(-2L, 2L).random()).coerceIn(5, 100)
        
        // Drastic mutation if we change strategy
        if (Math.random() > 0.7) {
            dna.strategy = null // Reset strategy to re-probe
        }
    }
    private val _currentRttMs = MutableStateFlow(100L)
    val currentRttMs: StateFlow<Long> = _currentRttMs.asStateFlow()

    fun updateRtt(rtt: Long) {
        if (rtt in 10..2000) {
            val old = _currentRttMs.value
            _currentRttMs.value = (old * 0.8 + rtt * 0.2).toLong() // Exponential moving average
        }
    }

    fun getAdaptiveDelay1(): Long {
        return (_currentRttMs.value / 4).coerceIn(10L, 100L)
    }

    fun getAdaptiveDelay2(): Long {
        return (_currentRttMs.value / 8).coerceIn(5L, 50L)
    }

    fun updateNetworkType(type: NetworkType) {
        if (_currentNetworkType.value != type) {
            _currentNetworkType.value = type
            reOptimize()
            ProxyStats.logRecovery("CORE: Network changed to $type. Re-optimizing parameters.")
        }
    }

    private val _currentNetworkType = MutableStateFlow(NetworkType.UNKNOWN)
    val currentNetworkType: StateFlow<NetworkType> = _currentNetworkType.asStateFlow()

    // Separate scores map for WIFI and MOBILE profiles
    private val wifiStrategyScores = ConcurrentHashMap<BypassStrategy, Int>()
    private val mobileStrategyScores = ConcurrentHashMap<BypassStrategy, Int>()

    // Category-specific scores maps
    private val wifiCategoryScores = ConcurrentHashMap<HostCategory, ConcurrentHashMap<BypassStrategy, Int>>()
    private val mobileCategoryScores = ConcurrentHashMap<HostCategory, ConcurrentHashMap<BypassStrategy, Int>>()

    private val defaultScores = mapOf(
        BypassStrategy.FAKE_PACKET to 500,
        BypassStrategy.TCP_OOB_DESYNC to 400,
        BypassStrategy.SNI_TRIPLE to 350,
        BypassStrategy.SNI_SPLIT to 300,
        BypassStrategy.TLS_PAD to 250,
        BypassStrategy.TLS_GREASE to 250,
        BypassStrategy.TLS_DIRTY to 100,
        BypassStrategy.FRAG_3_5 to 200,
        BypassStrategy.CHUNKY to 100,
        BypassStrategy.HOST_MIXED to 100,
        BypassStrategy.HOST_CASE to 100,
        BypassStrategy.HEADER_SPLIT to 100,
        BypassStrategy.HTTP_SPACE to 50,
        BypassStrategy.HTTP_TAB to 50,
        BypassStrategy.SLOW_SEND to 300,
        BypassStrategy.OOB_DESYNC to 300,
        BypassStrategy.TCP_ZERO_WINDOW to 250,
        BypassStrategy.GHOST_PACKETS to 200,
        BypassStrategy.DIRECT to 1
    )

    private val strategyScores = ConcurrentHashMap<BypassStrategy, Int>().apply {
        putAll(defaultScores)
    }

    private var lastSaveTime = 0L

    private val _isProbing = MutableStateFlow(false)
    val isProbing: StateFlow<Boolean> = _isProbing.asStateFlow()

    fun reOptimize() {
        if (!isAutoTuning) return
        
        val successRate = ProxyStats.getSuccessRate()
        val censorshipIntensity = ProxyStats.censorshipIntensity.value
        
        // Select network-specific strategy scores
        val currentScores = when (_currentNetworkType.value) {
            NetworkType.WIFI -> {
                if (wifiStrategyScores.isEmpty()) wifiStrategyScores.putAll(defaultScores)
                wifiStrategyScores
            }
            else -> {
                if (mobileStrategyScores.isEmpty()) mobileStrategyScores.putAll(defaultScores)
                mobileStrategyScores
            }
        }

        // Auto-switch trigger: High censorship or poor success rate
        val needsStrategySwitch = successRate < 50 || (censorshipIntensity > 70 && successRate < 80)

        if (successRate > 90 && censorshipIntensity < 30) {
            // Very stable, rarely mutate
            if (Math.random() > 0.98) {
                frag1 = (frag1 + listOf(-1, 1).random()).coerceIn(1, 15)
                delay1 = (delay1 + listOf(-1L, 1L).random()).coerceIn(5, 50)
                _isProbing.value = true
                kotlinx.coroutines.CoroutineScope(Dispatchers.Default).launch {
                    delay(2000)
                    _isProbing.value = false
                }
            }
        } else if (successRate > 70 && censorshipIntensity < 60) {
            // Good, but can improve
            if (Math.random() > 0.7) {
                frag1 = (frag1 + listOf(-2, -1, 1, 2).random()).coerceIn(1, 10)
                frag2 = (frag2 + listOf(-2, -1, 1, 2).random()).coerceIn(1, 15)
                ProxyStats.logRecovery("Auto-tuning parameters: frag1=$frag1, frag2=$frag2")
            }
        } else if (successRate < 70 || censorshipIntensity > 60) {
            // Unstable or high censorship: aggressive mutation
            if (Math.random() > 0.7) {
                frag1 = (frag1 + listOf(-1, 1).random()).coerceIn(1, 10)
                frag2 = (frag2 + listOf(-1, 1).random()).coerceIn(2, 20)
                delay1 = (delay1 + listOf(-2L, 2L).random()).coerceIn(10, 100)
                _isProbing.value = true
                kotlinx.coroutines.CoroutineScope(Dispatchers.Default).launch {
                    delay(3000)
                    _isProbing.value = false
                }
            }
        } else {
            // Poor performance, mutate more controlled
            if (Math.random() > 0.5) {
                // Re-attempt with slightly different parameters
                frag1 = (2..8).random()
                frag2 = (3..12).random()
                ProxyStats.logRecovery("Tuning parameters: frag1=$frag1, frag2=$frag2")
            } else {
                // Periodically switch default strategy if things are really bad
                if (needsStrategySwitch) {
                    val bestStrategy = currentScores.maxByOrNull { it.value }?.key 
                        ?: BypassStrategy.entries.filter { it != BypassStrategy.DIRECT && it != _currentStrategy.value }.random()
                    
                    if (bestStrategy != _currentStrategy.value) {
                        _currentStrategy.value = bestStrategy
                        ProxyStats.logRecovery("Auto-switched base strategy for ${_currentNetworkType.value} to best-performing: ${bestStrategy.name} (SuccessRate: $successRate, Censorship: $censorshipIntensity)")
                    }
                }
            }
        }
    }

    fun panicOptimize() {
        ProxyStats.logRecovery("CRITICAL: Entering Panic Optimization Mode. Force-switching to most aggressive strategies.")
        _currentStrategy.value = BypassStrategy.FAKE_PACKET
        frag1 = 1
        frag2 = 2
        blockQuic = true
        RobustResolver.clearCache()
        
        // Boost scores for heavy strategies to ensure they are picked for subsequent sessions
        val networkScores = getNetworkScoresMap()
        networkScores[BypassStrategy.FAKE_PACKET] = 1000
        networkScores[BypassStrategy.TCP_OOB_DESYNC] = 900
        networkScores[BypassStrategy.SNI_TRIPLE] = 850
        networkScores[BypassStrategy.TCP_ZERO_WINDOW] = 800
    }

    fun initialize(context: android.content.Context) {
        val prefs = context.getSharedPreferences("bypass_prefs", android.content.Context.MODE_PRIVATE)
        
        // Load general scores
        for (strategy in BypassStrategy.entries) {
            val score = prefs.getInt("score_${strategy.name}", -1)
            if (score != -1) {
                strategyScores[strategy] = score
            }
        }
        
        // Load some host cache
        val hostCacheStr = prefs.getString("host_cache", "")
        if (!hostCacheStr.isNullOrEmpty()) {
            hostCacheStr.split(";").forEach { entry ->
                val parts = entry.split(",")
                if (parts.size == 3) {
                    try {
                        val host = parts[0]
                        val strategy = BypassStrategy.valueOf(parts[1])
                        val count = parts[2].toInt()
                        hostStrategyCache[host] = strategy to count
                    } catch (e: Exception) {}
                }
            }
        }

        // Load host TTL cache
        val hostTtlStr = prefs.getString("host_ttl_cache", "")
        if (!hostTtlStr.isNullOrEmpty()) {
            hostTtlStr.split(";").forEach { entry ->
                val parts = entry.split(",")
                if (parts.size == 2) {
                    try {
                        val host = parts[0]
                        val ttlVal = parts[1].toInt()
                        hostTtlMap[host] = ttlVal
                    } catch (e: Exception) {}
                }
            }
        }

        // Load Host DNA
        val dnaStr = prefs.getString("host_dna_data", "")
        if (!dnaStr.isNullOrEmpty()) {
            dnaStr.split(";").forEach { entry ->
                val parts = entry.split(",")
                if (parts.size >= 4) {
                    try {
                        val host = parts[0]
                        val f1 = parts[1].toInt()
                        val f2 = parts[2].toInt()
                        val d1 = parts[3].toLong()
                        val strat = if (parts.size > 4 && parts[4] != "null") BypassStrategy.valueOf(parts[4]) else null
                        hostDnas[host] = HostDna(f1, f2, d1, strat)
                    } catch (e: Exception) {}
                }
            }
        }

        // Load Dynamic Censorship
        val censorStr = prefs.getString("dynamic_censorship_data", "")
        if (!censorStr.isNullOrEmpty()) {
            censorStr.split(";").forEach { entry ->
                val parts = entry.split(",")
                if (parts.size == 2) {
                    try {
                        dynamicallyCensoredHosts[parts[0]] = parts[1].toLong()
                    } catch (e: Exception) {}
                }
            }
        }
    }

    fun saveScores(context: android.content.Context) {
        val now = System.currentTimeMillis()
        if (now - lastSaveTime < 30000) return // Don't save too often
        lastSaveTime = now

        val prefs = context.getSharedPreferences("bypass_prefs", android.content.Context.MODE_PRIVATE)
        val editor = prefs.edit()
        
        for ((strategy, score) in strategyScores) {
            editor.putInt("score_${strategy.name}", score)
        }
        
        // Save top 100 entries from host cache
        val cacheStr = hostStrategyCache.entries
            .sortedByDescending { it.value.second }
            .take(100)
            .joinToString(";") { "${it.key},${it.value.first.name},${it.value.second}" }
        editor.putString("host_cache", cacheStr)

        // Save host TTL cache
        val ttlStr = hostTtlMap.entries
            .take(100)
            .joinToString(";") { "${it.key},${it.value}" }
        editor.putString("host_ttl_cache", ttlStr)

        // Save Host DNA (top 200 active hosts)
        val dnaStr = hostDnas.entries
            .filter { System.currentTimeMillis() - it.value.lastSuccess < 7 * 24 * 60 * 60 * 1000L }
            .take(200)
            .joinToString(";") { "${it.key},${it.value.frag1},${it.value.frag2},${it.value.delay1},${it.value.strategy?.name ?: "null"}" }
        editor.putString("host_dna_data", dnaStr)

        // Save Dynamic Censorship
        val censorStr = dynamicallyCensoredHosts.entries
            .filter { System.currentTimeMillis() - it.value < 2 * 24 * 60 * 60 * 1000L }
            .joinToString(";") { "${it.key},${it.value}" }
        editor.putString("dynamic_censorship_data", censorStr)
        
        editor.apply()
    }

    fun resetToDefaults() {
        strategyScores.clear()
        strategyScores.putAll(defaultScores)
        hostStrategyCache.clear()
        wifiStrategyScores.clear()
        wifiStrategyScores.putAll(defaultScores)
        mobileStrategyScores.clear()
        mobileStrategyScores.putAll(defaultScores)
        Log.i("BypassConfig", "All scores RESET to defaults due to low success rate")
    }

    // Host-specific strategy cache: Host -> (Strategy, SuccessCount)
    private val hostStrategyCache = ConcurrentHashMap<String, Pair<BypassStrategy, Int>>()
    private val hostCacheMaxEntries = 500

    private val _currentFragSize = AtomicInteger(1)
    private val _currentFragSizeState = MutableStateFlow(1)
    val currentFragSizeState: StateFlow<Int> = _currentFragSizeState.asStateFlow()

    private val successWindow = java.util.concurrent.ConcurrentLinkedQueue<Boolean>()
    private val windowSize = 50

    fun adjustFragmentation(success: Boolean) {
        successWindow.add(success)
        while (successWindow.size > windowSize) successWindow.poll()
        
        val successRate = successWindow.count { it }.toDouble() / successWindow.size.coerceAtLeast(1)
        
        if (success) {
            // If success rate is high (>90%), try to increase fragment size to improve performance
            if (successRate > 0.9 && _currentFragSize.get() < 8 && Math.random() > 0.8) {
                _currentFragSize.incrementAndGet()
            }
        } else {
            // If failure, immediately decrease fragment size for better evasion
            if (_currentFragSize.get() > 1) {
                _currentFragSize.decrementAndGet()
            } else {
                _currentFragSize.set(1)
            }
        }
        _currentFragSizeState.value = _currentFragSize.get()
    }

    fun getCurrentFragSize() = _currentFragSize.get()

    fun isHostCensored(host: String): Boolean {
        val lower = host.lowercase(java.util.Locale.ROOT)
        val blocked = mutableListOf(
            "youtube", "googlevideo", "ytimg", "ggpht", "google", "telegram", "t.me",
            "instagram", "facebook", "twitter", "x.com", "discord", "chatgpt", "openai"
        )
        
        // Add dynamically detected hosts
        dynamicallyCensoredHosts.keys().asSequence().forEach { 
            val dynamicTime = dynamicallyCensoredHosts[it] ?: 0L
            if (System.currentTimeMillis() - dynamicTime < 86400000) { // Keep for 24h
                blocked.add(it)
            } else {
                dynamicallyCensoredHosts.remove(it)
            }
        }
        
        return blocked.any { lower.contains(it) }
    }

    private val dynamicallyCensoredHosts = ConcurrentHashMap<String, Long>()
    private val hostSuccessStrategies = ConcurrentHashMap<String, BypassStrategy>()
    private val hostSuccessCount = ConcurrentHashMap<String, Int>()

    fun markHostAsCensored(host: String) {
        if (host.length > 3 && !isHostCensored(host)) {
            dynamicallyCensoredHosts[host] = System.currentTimeMillis()
            ProxyStats.logRecovery("CORE: Identified $host as CENSORED host.")
        }
    }

    private fun getNetworkScoresMap(): ConcurrentHashMap<BypassStrategy, Int> {
        val map = when (_currentNetworkType.value) {
            NetworkType.WIFI -> wifiStrategyScores
            else -> mobileStrategyScores
        }
        if (map.isEmpty()) map.putAll(defaultScores)
        return map
    }

    fun recordSuccess(strategy: BypassStrategy, context: android.content.Context? = null) {
        val currentScore = strategyScores[strategy] ?: 100
        strategyScores[strategy] = (currentScore + 30).coerceAtMost(1000)
        
        // Update network-specific score
        val networkScores = getNetworkScoresMap()
        networkScores[strategy] = (networkScores[strategy] ?: 100) + 30
        
        if (context != null) saveScores(context)
    }

    fun recordSuccessForHost(host: String, strategy: BypassStrategy, context: android.content.Context? = null) {
        adjustFragmentation(true)
        ProxyStats.recordCensorshipEvent(false)
        ProxyStats.recordGlobalSuccess()
        
        // DNA Evolution: Optimizing for performance when successful
        val dna = getDnaForHost(host)
        dna.lastSuccess = System.currentTimeMillis()
        dna.strategy = strategy // Persist winning strategy in DNA

        if (Math.random() > 0.8 && dna.frag1 < 10) {
            dna.frag1++ 
            if (dna.delay1 > 10) dna.delay1 -= 1
        }

        // Strategy memory: evolution of "known working" strategies
        val currentBest = hostSuccessStrategies[host]
        if (currentBest == strategy) {
            hostSuccessCount[host] = (hostSuccessCount[host] ?: 0) + 1
        } else {
            hostSuccessStrategies[host] = strategy
            hostSuccessCount[host] = 1
        }

        // Clear failure history on success
        hostFailedStrategies.remove(host)
        lastFailureTime.remove(host)
        hostConsecutiveFailures.remove(host)

        if (strategy == BypassStrategy.FAKE_PACKET) {
            val expTtl = hostExplorationTtl[host] ?: 3
            hostTtlMap[host] = expTtl
        }

        if (hostStrategyCache.size > hostCacheMaxEntries) {
            hostStrategyCache.clear() // Simple eviction
        }
        val current = hostStrategyCache[host]
        if (current != null && current.first == strategy) {
            hostStrategyCache[host] = strategy to (current.second + 1)
        } else {
            hostStrategyCache[host] = strategy to 1
        }
        
        // Boost strategy score for this category
        val category = HostClassifier.classify(host)
        val scoresMap = getCategoryScoresMap(category)
        scoresMap[strategy] = (scoresMap[strategy] ?: 100) + 10
        strategyScores[strategy] = (strategyScores[strategy] ?: 100) + 2
        
        // Boost network-specific score
        val networkScores = getNetworkScoresMap()
        networkScores[strategy] = (networkScores[strategy] ?: 100) + 5
        
        if (context != null) {
            saveScores(context)
        }
    }

    fun recordFailureForHost(host: String, strategy: BypassStrategy, isCritical: Boolean = false, context: android.content.Context? = null) {
        adjustFragmentation(false)
        ProxyStats.recordCensorshipEvent(true)
        val category = HostClassifier.classify(host)
        val scoresMap = getCategoryScoresMap(category)
        
        val penalty = if (isCritical) 25 else 10
        scoresMap[strategy] = ((scoresMap[strategy] ?: 100) - penalty).coerceAtLeast(0)
        strategyScores[strategy] = ((strategyScores[strategy] ?: 100) - 2).coerceAtLeast(0)
        
        // Add network-specific penalty
        val networkScores = getNetworkScoresMap()
        networkScores[strategy] = ((networkScores[strategy] ?: 100) - (penalty / 2)).coerceAtLeast(10)
        
        // Add to failed history
        val failedSet = hostFailedStrategies.getOrPut(host) { java.util.Collections.synchronizedSet(mutableSetOf()) }
        failedSet.add(strategy)
        lastFailureTime[host] = System.currentTimeMillis()

        if (strategy == BypassStrategy.FAKE_PACKET) {
            val expTtl = hostExplorationTtl[host] ?: 3
            if (expTtl < 12) {
                hostExplorationTtl[host] = expTtl + 1
                ProxyStats.logRecovery("Adjusting exploration FAKE_PACKET TTL for $host to ${expTtl + 1}")
            } else {
                hostExplorationTtl[host] = 3
            }
        }

        val failures = (hostConsecutiveFailures[host] ?: 0) + 1
        hostConsecutiveFailures[host] = failures
        if (failures >= 2) {
            markHostAsCensored(host)
            mutateDnaForHost(host)
        }
        if (failures >= 3 && context != null) {
            triggerDnsPoisoningCorrection(host, context)
            hostConsecutiveFailures.remove(host)
        }

        // If critical failure, remove from host cache and reset DNS
        if (isCritical) {
            hostStrategyCache.remove(host)
            hostSuccessStrategies.remove(host)
            hostSuccessCount.remove(host)
            RobustResolver.clearCacheForHost(host)
            ProxyStats.logRecovery("CORE: Critical failure for $host. Resetting strategy and DNS cache.")
        }
        if (context != null) saveScores(context)
    }

    private fun triggerDnsPoisoningCorrection(host: String, context: android.content.Context) {
        val vpn = context as? android.net.VpnService ?: return
        kotlinx.coroutines.CoroutineScope(java.util.concurrent.Executors.newCachedThreadPool().asCoroutineDispatcher()).launch {
            try {
                Log.i("BypassConfig", "Detecting consecutive failures for $host. Starting DNS self-repair...")
                RobustResolver.clearCacheForHost(host)
                val standardIps = try {
                    java.net.InetAddress.getAllByName(host).toList()
                } catch (e: Exception) {
                    emptyList()
                }
                val secureIps = try {
                    RobustResolver.resolve(host, vpn, forceSecure = true)
                } catch (e: Exception) {
                    emptyList()
                }
                
                if (standardIps.isNotEmpty() && secureIps.isNotEmpty()) {
                    val standardSet = standardIps.mapNotNull { it.hostAddress }.toSet()
                    val secureSet = secureIps.mapNotNull { it.hostAddress }.toSet()
                    
                    val intersection = standardSet.intersect(secureSet)
                    if (intersection.isEmpty()) {
                        Log.w("BypassConfig", "DNS Poisoning DETECTED for $host! Standard IPs: $standardSet, Secure IPs: $secureSet")
                        ProxyStats.recordCensorshipEvent(true)
                        ProxyStats.recordCensorshipEvent(true)
                        ProxyStats.recordCensorshipEvent(true)
                        for (poisonedIp in standardSet) {
                            RobustResolver.registerPoisonedIp(poisonedIp)
                        }
                        RobustResolver.populateCache(host, secureIps)
                        ProxyStats.logRecovery("DNS self-repair: corrected IPs for $host using secure DoH")
                    }
                }
            } catch (e: Exception) {
                Log.e("BypassConfig", "DNS self-repair failed for $host: ${e.message}")
            }
        }
    }

    fun recordFailure(strategy: BypassStrategy, isCritical: Boolean = false, context: android.content.Context? = null) {
        val penalty = if (isCritical) 20 else 5
        strategyScores[strategy] = ((strategyScores[strategy] ?: 100) - penalty).coerceAtLeast(10)
        if (context != null) saveScores(context)
    }

    init {
        wifiStrategyScores.putAll(defaultScores)
        mobileStrategyScores.putAll(defaultScores)
        
        for (category in HostCategory.values()) {
            val wifiMap = ConcurrentHashMap<BypassStrategy, Int>()
            wifiMap.putAll(defaultScores)
            wifiCategoryScores[category] = wifiMap
            
            val mobileMap = ConcurrentHashMap<BypassStrategy, Int>()
            mobileMap.putAll(defaultScores)
            mobileCategoryScores[category] = mobileMap
        }
    }

    fun getCategoryScoresMap(category: HostCategory): ConcurrentHashMap<BypassStrategy, Int> {
        return if (_currentNetworkType.value == NetworkType.WIFI) {
            wifiCategoryScores[category] ?: wifiCategoryScores.getOrPut(category) { ConcurrentHashMap<BypassStrategy, Int>().apply { putAll(defaultScores) } }
        } else {
            mobileCategoryScores[category] ?: mobileCategoryScores.getOrPut(category) { ConcurrentHashMap<BypassStrategy, Int>().apply { putAll(defaultScores) } }
        }
    }

    fun getStrategyScore(strategy: BypassStrategy): Int {
        return strategyScores[strategy] ?: 100
    }

    fun getStrategyScores(): Map<BypassStrategy, Int> {
        return strategyScores.toMap()
    }

    // Strategy history to prevent oscillation: Host -> Set<BypassStrategy> (failed ones recently)
    private val hostFailedStrategies = ConcurrentHashMap<String, MutableSet<BypassStrategy>>()
    private val lastFailureTime = ConcurrentHashMap<String, Long>()

    fun resolveStrategyForHost(host: String): BypassStrategy {
        if (!isAutoTuning) {
            return _currentStrategy.value
        }
        
        // 0. Use Host DNA strategy if available and proven
        val dna = getDnaForHost(host)
        dna.strategy?.let { return it }

        // 1. If we have a very stable strategy for this host (e.g. 5+ successes), use it
        if ((hostSuccessCount[host] ?: 0) >= 5) {
            val best = hostSuccessStrategies[host]
            if (best != null && hostFailedStrategies[host]?.contains(best) != true) {
                return best
            }
        }

        val now = System.currentTimeMillis()
        // Clear old failure history (e.g. after 10 minutes)
        if (now % 100 == 0L) { // Periodic cleanup
            lastFailureTime.entries.removeIf { now - it.value > 600000 }
        }

        // 1. Check host-specific cache
        val cached = hostStrategyCache[host]
        if (cached != null && cached.second > 3) {
            return cached.first
        }
        
        // 2. Check root domain cache
        val domainParts = host.split(".")
        if (domainParts.size > 2) {
            val rootDomain = domainParts.takeLast(2).joinToString(".")
            hostStrategyCache.entries.find { it.key.endsWith(".$rootDomain") && it.value.second > 5 }?.let {
                return it.value.first
            }
        }

        val category = HostClassifier.classify(host)
        val scoresMap = getCategoryScoresMap(category)
        val failed = hostFailedStrategies[host] ?: emptySet<BypassStrategy>()
        
        // 3. Probing: Weighted Random selection excluding known failed strategies for this host
        val strategies = BypassStrategy.entries.filter { it != BypassStrategy.DIRECT && it !in failed }
        val effectiveStrategies = if (strategies.isEmpty()) BypassStrategy.entries.filter { it != BypassStrategy.DIRECT } else strategies
        
        val censorship = ProxyStats.censorshipIntensity.value
        
        val adjustedScores = effectiveStrategies.associateWith { strategy ->
            val baseScore = (scoresMap[strategy] ?: 100).coerceAtLeast(1)
            when {
                censorship >= 65 -> {
                    // Severe block: boost heavy evasion strategies
                    if (strategy == BypassStrategy.FAKE_PACKET || 
                        strategy == BypassStrategy.TCP_OOB_DESYNC || 
                        strategy == BypassStrategy.SNI_MANGLE || 
                        strategy == BypassStrategy.SNI_TRIPLE ||
                        strategy == BypassStrategy.TCP_ZERO_WINDOW) {
                        baseScore * 3
                    } else if (strategy == BypassStrategy.DIRECT || 
                               strategy == BypassStrategy.CHUNKY || 
                               strategy == BypassStrategy.HTTP_SPACE || 
                               strategy == BypassStrategy.HTTP_TAB) {
                        (baseScore / 4).coerceAtLeast(1)
                    } else {
                        baseScore
                    }
                }
                censorship < 25 -> {
                    // Clean environment: boost lightweight, fast strategies
                    if (strategy == BypassStrategy.DIRECT || 
                        strategy == BypassStrategy.CHUNKY || 
                        strategy == BypassStrategy.SNI_SPLIT) {
                        baseScore * 2
                    } else if (strategy == BypassStrategy.FAKE_PACKET || 
                               strategy == BypassStrategy.TCP_OOB_DESYNC || 
                               strategy == BypassStrategy.SNI_MANGLE) {
                        (baseScore / 2).coerceAtLeast(1)
                    } else {
                        baseScore
                    }
                }
                else -> baseScore
            }
        }
        
        val totalScore = adjustedScores.values.sum()
        
        if (totalScore > 0) {
            var r = (0 until totalScore).random()
            for (strategy in effectiveStrategies) {
                r -= (adjustedScores[strategy] ?: 1).coerceAtLeast(1)
                if (r < 0) return strategy
            }
        }

        return _currentStrategy.value
    }

    // Stores the confirmed working TTL per host
    private val hostTtlMap = ConcurrentHashMap<String, Int>()
    
    // Stores the active exploration TTL for hosts that haven't succeeded yet
    private val hostExplorationTtl = ConcurrentHashMap<String, Int>()

    // Consecutive failures for DNS self-repair
    private val hostConsecutiveFailures = ConcurrentHashMap<String, Int>()

    fun getSessionConfig(host: String, strategy: BypassStrategy, currentRtt: Long): SessionConfig {
        val dna = getDnaForHost(host)
        var f1 = dna.frag1
        var f2 = dna.frag2
        var f3 = 2
        var d1 = dna.delay1
        var d2 = BypassConfig.getAdaptiveDelay2()
        var ttl = 3
        
        if (!isAutoTuning) {
            return SessionConfig(
                strategy = strategy,
                frag1 = BypassConfig.frag1,
                frag2 = BypassConfig.frag2,
                frag3 = BypassConfig.frag3,
                delay1 = BypassConfig.delay1,
                delay2 = BypassConfig.delay2,
                fakeTtl = BypassConfig.fakeTtl
            )
        }

        when (strategy) {
            BypassStrategy.FAKE_PACKET -> {
                if (isHostCensored(host)) {
                    f1 = (f1 / 2).coerceAtLeast(1)
                    d1 = (d1 * 1.5).toLong()
                }
                
                val workingTtl = hostTtlMap[host]
                if (workingTtl != null) {
                    ttl = workingTtl
                } else {
                    val expTtl = hostExplorationTtl.getOrPut(host) { 3 }
                    ttl = expTtl
                }
            }
            BypassStrategy.SNI_SPLIT, BypassStrategy.SNI_TRIPLE -> {
                f1 = dna.frag1.coerceIn(1, 5)
                f2 = dna.frag2.coerceIn(2, 10)
                d1 = dna.delay1.coerceIn(15, 150)
            }
            BypassStrategy.SNI_MANGLE -> {
                f1 = 1
                d1 = dna.delay1.coerceIn(5, 50)
            }
            BypassStrategy.TLS_DIRTY -> {
                f1 = (dna.frag1 % 5).coerceAtLeast(1)
                d1 = dna.delay1.coerceIn(10, 80)
            }
            BypassStrategy.FRAG_3_5 -> {
                f1 = dna.frag1.coerceIn(2, 12)
                f2 = (f1 + dna.frag2 % 10).coerceAtLeast(f1 + 1)
                d1 = dna.delay1.coerceIn(10, 100)
            }
            BypassStrategy.CHUNKY -> {
                f1 = (dna.frag1 % 3).coerceAtLeast(1)
                d1 = dna.delay1.coerceIn(5, 40)
            }
            BypassStrategy.HOST_CASE, BypassStrategy.HOST_MIXED -> {
                f1 = 1
                d1 = dna.delay1.coerceIn(5, 30)
            }
            BypassStrategy.RAND_SPLIT -> {
                f1 = dna.frag1.coerceIn(1, 40)
                d1 = dna.delay1.coerceIn(10, 100)
            }
            BypassStrategy.HEADER_SPLIT -> {
                f1 = (dna.frag1 % 4).coerceAtLeast(1)
                d1 = dna.delay1.coerceIn(20, 120)
            }
            BypassStrategy.TCP_OOB_DESYNC -> {
                f1 = 1
                d1 = dna.delay1.coerceIn(5, 60)
            }
            BypassStrategy.HTTP_SPACE, BypassStrategy.HTTP_TAB -> {
                f1 = 1
                d1 = dna.delay1.coerceIn(5, 40)
            }
            BypassStrategy.WINDOW_SIZE -> {
                f1 = 0
                d1 = 10L
            }
            BypassStrategy.SLOW_SEND -> {
                f1 = 1
                d1 = dna.delay1.coerceIn(30, 150)
            }
            BypassStrategy.OOB_DESYNC -> {
                f1 = (dna.frag1 % 5).coerceAtLeast(1)
                d1 = 15L
            }
            BypassStrategy.TCP_ZERO_WINDOW -> {
                f1 = 1
                d1 = dna.delay1.coerceIn(5, 50)
            }
            BypassStrategy.TLS_PAD -> {
                f1 = dna.frag1.coerceIn(100, 800)
                d1 = dna.delay1.coerceIn(5, 60)
            }
            BypassStrategy.TLS_GREASE -> {
                f1 = (dna.frag1 % 8).coerceAtLeast(1)
                d1 = dna.delay1.coerceIn(10, 120)
            }
            else -> {}
        }

        return SessionConfig(
            strategy = strategy,
            frag1 = f1,
            frag2 = f2,
            frag3 = f3,
            delay1 = d1,
            delay2 = d2,
            fakeTtl = ttl
        )
    }

    fun resolveSessionConfigForHost(host: String): SessionConfig {
        val strat = resolveStrategyForHost(host)
        return getSessionConfig(host, strat, _currentRttMs.value)
    }

    fun switchNetworkProfile(context: android.content.Context, netType: NetworkType) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", android.content.Context.MODE_PRIVATE)
        
        // 1. Backup current active scores to SharedPreferences and their respective profile map
        val prevType = _currentNetworkType.value
        if (prevType == NetworkType.WIFI) {
            wifiStrategyScores.putAll(strategyScores)
            saveProfileScores(context, "wifi")
        } else if (prevType == NetworkType.MOBILE) {
            mobileStrategyScores.putAll(strategyScores)
            saveProfileScores(context, "mobile")
        }
        
        _currentNetworkType.value = netType
        
        // 2. Load strategy scores for the target profile
        strategyScores.clear()
        if (netType == NetworkType.WIFI) {
            loadProfileScores(context, "wifi", wifiStrategyScores)
            strategyScores.putAll(wifiStrategyScores)
        } else if (netType == NetworkType.MOBILE) {
            loadProfileScores(context, "mobile", mobileStrategyScores)
            strategyScores.putAll(mobileStrategyScores)
        } else {
            strategyScores.putAll(defaultScores)
        }
        
        // 3. Set the active strategy (or pick the best one for this network)
        val profileStrategyKey = "selected_strategy_${netType.name}"
        if (prefs.contains(profileStrategyKey)) {
            val savedStrat = prefs.getString(profileStrategyKey, null)
            if (savedStrat != null) {
                try {
                    _currentStrategy.value = BypassStrategy.valueOf(savedStrat)
                } catch (e: Exception) {}
            }
        } else {
            val best = strategyScores.entries.maxByOrNull { it.value }?.key ?: BypassStrategy.SNI_SPLIT
            _currentStrategy.value = best
        }
        
        ProxyStats.logRecovery("Switched profile to ${netType.name}. Active Strategy: ${_currentStrategy.value.name}")
    }

    private fun saveProfileScores(context: android.content.Context, prefix: String) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", android.content.Context.MODE_PRIVATE)
        val editor = prefs.edit()
        val scoresMap = if (prefix == "wifi") wifiStrategyScores else mobileStrategyScores
        for (strategy in BypassStrategy.values()) {
            editor.putInt("${prefix}_score_${strategy.name}", scoresMap[strategy] ?: 100)
        }
        editor.apply()
        saveCategoryProfileScores(context)
    }

    private fun saveCategoryProfileScores(context: android.content.Context) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", android.content.Context.MODE_PRIVATE)
        val editor = prefs.edit()
        for (prefix in listOf("wifi", "mobile")) {
            val map = if (prefix == "wifi") wifiCategoryScores else mobileCategoryScores
            for (category in HostCategory.values()) {
                val catScores = map[category] ?: continue
                for (strategy in BypassStrategy.values()) {
                    editor.putInt("${prefix}_score_${category.name}_${strategy.name}", catScores[strategy] ?: 100)
                }
            }
        }
        editor.apply()
    }

    private fun loadProfileScores(context: android.content.Context, prefix: String, targetMap: ConcurrentHashMap<BypassStrategy, Int>) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", android.content.Context.MODE_PRIVATE)
        var hasScores = false
        for (strategy in BypassStrategy.values()) {
            val key = "${prefix}_score_${strategy.name}"
            if (prefs.contains(key)) {
                targetMap[strategy] = prefs.getInt(key, 100)
                hasScores = true
            }
        }
        if (!hasScores) {
            targetMap.putAll(defaultScores)
        }
    }

    private fun loadCategoryProfileScores(context: android.content.Context) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", android.content.Context.MODE_PRIVATE)
        for (prefix in listOf("wifi", "mobile")) {
            val map = if (prefix == "wifi") wifiCategoryScores else mobileCategoryScores
            for (category in HostCategory.values()) {
                val catScores = map[category] ?: continue
                for (strategy in BypassStrategy.values()) {
                    val key = "${prefix}_score_${category.name}_${strategy.name}"
                    if (prefs.contains(key)) {
                        catScores[strategy] = prefs.getInt(key, defaultScores[strategy] ?: 100)
                    }
                }
            }
        }
    }

    fun loadTuningSettings(context: android.content.Context) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", android.content.Context.MODE_PRIVATE)
        isAutoTuning = prefs.getBoolean("is_auto_tuning", true)
        blockQuic = prefs.getBoolean("block_quic", true)
        
        // Load profiles scores from disk
        loadProfileScores(context, "wifi", wifiStrategyScores)
        loadProfileScores(context, "mobile", mobileStrategyScores)
        loadCategoryProfileScores(context)
        
        // Load active scores map depending on the current network type
        strategyScores.clear()
        if (_currentNetworkType.value == NetworkType.WIFI) {
            strategyScores.putAll(wifiStrategyScores)
        } else if (_currentNetworkType.value == NetworkType.MOBILE) {
            strategyScores.putAll(mobileStrategyScores)
        } else {
            // General fallback
            for (strategy in BypassStrategy.values()) {
                val scoreKey = "strategy_score_${strategy.name}"
                strategyScores[strategy] = prefs.getInt(scoreKey, defaultScores[strategy] ?: 100)
            }
        }
        
        // Load active strategy selection
        val profileStrategyKey = if (_currentNetworkType.value != NetworkType.UNKNOWN) "selected_strategy_${_currentNetworkType.value.name}" else "selected_strategy"
        val savedStrategyStr = prefs.getString(profileStrategyKey, prefs.getString("selected_strategy", null))
        if (savedStrategyStr != null) {
            try {
                val strat = BypassStrategy.valueOf(savedStrategyStr)
                _currentStrategy.value = strat
            } catch (e: Exception) {}
        }

        if (!isAutoTuning) {
            frag1 = prefs.getInt("param_frag1", 3)
            frag2 = prefs.getInt("param_frag2", 5)
            frag3 = prefs.getInt("param_frag3", 2)
            delay1 = prefs.getLong("param_delay1", 25L)
            delay2 = prefs.getLong("param_delay2", 20L)
            fakeTtl = prefs.getInt("param_fake_ttl", 3)
        }
    }

    fun saveTuningSettings(context: android.content.Context) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", android.content.Context.MODE_PRIVATE)
        val editor = prefs.edit()
            .putBoolean("is_auto_tuning", isAutoTuning)
            .putBoolean("block_quic", blockQuic)
            .putInt("param_frag1", frag1)
            .putInt("param_frag2", frag2)
            .putInt("param_frag3", frag3)
            .putLong("param_delay1", delay1)
            .putLong("param_delay2", delay2)
            .putInt("param_fake_ttl", fakeTtl)
            
        if (_currentNetworkType.value != NetworkType.UNKNOWN) {
            editor.putString("selected_strategy_${_currentNetworkType.value.name}", _currentStrategy.value.name)
        } else {
            editor.putString("selected_strategy", _currentStrategy.value.name)
        }
        editor.apply()
        
        // Save current profile scores
        if (_currentNetworkType.value == NetworkType.WIFI) {
            wifiStrategyScores.putAll(strategyScores)
            saveProfileScores(context, "wifi")
        } else if (_currentNetworkType.value == NetworkType.MOBILE) {
            mobileStrategyScores.putAll(strategyScores)
            saveProfileScores(context, "mobile")
        } else {
            // General fallback save
            val edit = prefs.edit()
            for (strategy in BypassStrategy.values()) {
                edit.putInt("strategy_score_${strategy.name}", strategyScores[strategy] ?: 100)
            }
            edit.apply()
        }
        saveCategoryProfileScores(context)
    }
    
    fun setStrategy(newStrategy: BypassStrategy) {
        _currentStrategy.value = newStrategy
    }
    
    fun rotateGlobalStrategy() {
        val available = BypassStrategy.entries.filter { it != BypassStrategy.DIRECT && it != _currentStrategy.value }
        if (available.isNotEmpty()) {
            val best = available.maxByOrNull { strategyScores[it] ?: 100 }
            if (best != null && (strategyScores[best] ?: 100) > (strategyScores[_currentStrategy.value] ?: 100)) {
                _currentStrategy.value = best
                Log.i("BypassConfig", "Rotated global strategy to the best scoring option: ${best.name} (Score: ${strategyScores[best]})")
            } else {
                val chosen = available.random()
                _currentStrategy.value = chosen
                Log.i("BypassConfig", "Rotated global strategy to random option: ${chosen.name}")
            }
        }
    }
    
    private val lastSuccessTime = AtomicLong(System.currentTimeMillis())

    fun clearScores(context: android.content.Context) {
        strategyScores.clear()
        strategyScores.putAll(defaultScores)
        wifiStrategyScores.clear()
        wifiStrategyScores.putAll(defaultScores)
        mobileStrategyScores.clear()
        mobileStrategyScores.putAll(defaultScores)
        wifiCategoryScores.clear()
        mobileCategoryScores.clear()
        
        for (category in HostCategory.values()) {
            val wifiMap = ConcurrentHashMap<BypassStrategy, Int>()
            wifiMap.putAll(defaultScores)
            wifiCategoryScores[category] = wifiMap
            
            val mobileMap = ConcurrentHashMap<BypassStrategy, Int>()
            mobileMap.putAll(defaultScores)
            mobileCategoryScores[category] = mobileMap
        }
        
        saveTuningSettings(context)
        saveProfileScores(context, "wifi")
        saveProfileScores(context, "mobile")
        saveCategoryProfileScores(context)
    }
}

class PinkProxyServer(private val vpnService: VpnService, private val port: Int) {
    private var serverSocket: ServerSocket? = null
    private var isRunning = false
    // Use an unconstrained thread pool for blocking socket IO to prevent starvation (since Dispatchers.IO is capped at 64)
    private val proxyDispatcher = java.util.concurrent.Executors.newCachedThreadPool().asCoroutineDispatcher()
    private val scope = CoroutineScope(proxyDispatcher + SupervisorJob())
    
    private val bufferPool = java.util.concurrent.LinkedBlockingQueue<ByteArray>()
    private val POOL_SIZE = 128
    private val BUFFER_SIZE = 32768

    private fun getBuffer(size: Int = BUFFER_SIZE): ByteArray {
        if (size == BUFFER_SIZE) {
            return bufferPool.poll() ?: ByteArray(BUFFER_SIZE)
        }
        return ByteArray(size)
    }

    private fun releaseBuffer(buffer: ByteArray) {
        if (buffer.size == BUFFER_SIZE && bufferPool.size < POOL_SIZE) {
            bufferPool.offer(buffer)
        }
    }

    fun start() {
        if (isRunning) return
        isRunning = true
        scope.launch {
            try {
                serverSocket = ServerSocket().apply {
                    reuseAddress = true
                    soTimeout = 5000
                    bind(java.net.InetSocketAddress(java.net.InetAddress.getByName("127.0.0.1"), port), 50)
                }
                Log.d("PinkProxyServer", "Proxy server started on port $port")
                
                // Speed updater
                launch {
                    while (isRunning) {
                        delay(1000)
                        ProxyStats.updateSpeed()
                    }
                }
                
                startNetworkObserver()
                startProbingTask()
                RobustResolver.startBackgroundProber(scope, vpnService)

                while (isRunning) {
                    try {
                        val clientSocket = serverSocket?.accept()
                        if (clientSocket != null) {
                            handleClient(clientSocket)
                        }
                    } catch (e: java.net.SocketTimeoutException) {
                        // Just check isRunning
                    } catch (e: Exception) {
                        if (isRunning) {
                            Log.e("PinkProxyServer", "Accept error", e)
                            delay(1000)
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e("PinkProxyServer", "Server setup error", e)
            } finally {
                isRunning = false
                try { serverSocket?.close() } catch (e: Exception) {}
                serverSocket = null
            }
        }
    }

    fun stop() {
        isRunning = false
        try {
            serverSocket?.close()
        } catch (e: Exception) {}
        serverSocket = null
        scope.coroutineContext.cancelChildren()
    }

    private fun handleClient(clientSocket: Socket) = scope.launch {
        ProxyStats.addConnection()
        ProxyStats.addRequest()
        var targetSocket: Socket? = null
        var hostForStats: String? = null
        try {
            clientSocket.soTimeout = 10000 
            val clientInput = java.io.BufferedInputStream(clientSocket.getInputStream())
            val clientOutput = clientSocket.getOutputStream()

            clientInput.mark(4)
            val firstByte = clientInput.read()
            if (firstByte == 0x05) {
                handleSocks5Client(clientSocket, clientInput, clientOutput)
                return@launch
            }
            clientInput.reset()

            val requestLine = readLine(clientInput)
            if (requestLine.contains("generate_204")) {
                clientOutput.write("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".toByteArray())
                clientOutput.flush()
                return@launch
            }
            if (requestLine.startsWith("CONNECT")) {
                val parts = requestLine.split(" ")
                if (parts.size >= 2) {
                    val hostPort = parts[1].split(":")
                    val host = hostPort[0]
                    hostForStats = host
                    val session = BypassConfig.resolveSessionConfigForHost(host)
                    ProxyStats.logTraffic(host, session.strategy.name)
                    val destPort = if (hostPort.size > 1) {
                        try { hostPort[1].toInt() } catch (e: Exception) { 443 }
                    } else {
                        443
                    }

                    var headerCount = 0
                    while (headerCount < 100) {
                        val header = readLine(clientInput)
                        if (header.isEmpty()) break
                        headerCount++
                    }

                    val resolvedAddresses = try {
                        RobustResolver.resolve(host, vpnService)
                    } catch (e: Exception) {
                        ProxyStats.addError()
                        BypassConfig.recordFailureForHost(host = host, strategy = session.strategy, isCritical = true, context = vpnService)
                        throw e
                    }

                    // Happy Eyeballs: Connect to multiple IPs in parallel
                    targetSocket = connectTargetWithHappyEyeballs(resolvedAddresses, destPort, session.strategy)

                    if (targetSocket == null) {
                        Log.w("PinkProxyServer", "Initial Happy Eyeballs failed for $host. Retrying with secure DNS...")
                        // Fallback with secure DNS
                        try {
                            val secureAddresses = RobustResolver.resolve(host, vpnService, forceSecure = true)
                            targetSocket = connectTargetWithHappyEyeballs(secureAddresses, destPort, session.strategy)
                        } catch (ex: Exception) {
                            Log.e("PinkProxyServer", "Secure recovery failed for $host: ${ex.message}")
                        }
                    }

                    if (targetSocket == null) {
                        ProxyStats.addError()
                        BypassConfig.recordFailureForHost(host = host, strategy = session.strategy, isCritical = true, context = vpnService)
                        clientOutput.write("HTTP/1.1 502 Bad Gateway\r\n\r\n".toByteArray())
                        clientOutput.flush()
                        return@launch
                    }
                    
                    tuneSocket(targetSocket!!, session.strategy)
                    tuneSocket(clientSocket, session.strategy)

                    clientOutput.write("HTTP/1.1 200 Connection established\r\n\r\n".toByteArray())
                    clientOutput.flush()

                    // DPI Bypass: Randomized Fragmentation for TLS ClientHello
                    val buffer = getBuffer()
                    
                    var retryCount = 0
                    var currentTargetSocket = targetSocket!!
                    var currentSession = session
                    var read = 0
                    
                    clientInput.mark(32768)
                    
                    while (retryCount < 3 && isActive) {
                        if (retryCount > 0) {
                            clientInput.reset() // Replay the ClientHello
                        }
                        
                        clientSocket.soTimeout = 7000
                        read = try { clientInput.read(buffer) } catch (e: Exception) { -1 }
                        clientSocket.soTimeout = 300000
                        
                        if (read <= 0) break
                        
                        ProxyStats.addBytes(read.toLong())
                        val targetOutput = currentTargetSocket.getOutputStream()
                        
                        // Check for TLS Handshake (0x16 0x03)
                        if (read > 40 && buffer[0] == 0x16.toByte() && buffer[1] == 0x03.toByte()) {
                            var sniPos = TlsParser.findSniOffset(buffer, read)
                            if (sniPos == -1) {
                                val hostBytes = host.toByteArray()
                                if (hostBytes.size > 3) {
                                    for (i in 30 until (read - hostBytes.size).coerceAtMost(1500)) {
                                        var match = true
                                        for (j in hostBytes.indices) {
                                            val b1 = buffer[i + j]
                                            val b2 = hostBytes[j]
                                            if (b1 != b2) {
                                                val c1 = (b1.toInt() and 0xFF).toChar().lowercaseChar()
                                                val c2 = (b2.toInt() and 0xFF).toChar().lowercaseChar()
                                                if (c1 != c2) {
                                                    match = false
                                                    break
                                                }
                                            }
                                        }
                                        if (match) {
                                            sniPos = i
                                            break
                                        }
                                    }
                                }
                            }
                            applyBypass(currentTargetSocket, targetOutput, buffer, read, host, currentSession, sniPos)
                            BypassConfig.recordSuccessForHost(host, currentSession.strategy, vpnService)
                        } else if (read > 2) {
                            // Standard fragmentation for other traffic
                            targetOutput.write(buffer, 0, 2)
                            targetOutput.flush()
                            delay(10)
                            targetOutput.write(buffer, 2, read - 2)
                            targetOutput.flush()
                        } else {
                            targetOutput.write(buffer, 0, read)
                            targetOutput.flush()
                        }

                        val closeAction = {
                            try { currentTargetSocket.close() } catch (e: Exception) {}
                            try { clientSocket.close() } catch (e: Exception) {}
                        }

                        try {
                            coroutineScope {
                                val job1 = launch { proxyStream(clientInput, targetOutput, closeAction, host, isTargetSource = false, sessionStrategy = currentSession.strategy) }
                                val job2 = launch { 
                                    delay(50) 
                                    proxyStream(java.io.BufferedInputStream(currentTargetSocket.getInputStream()), clientOutput, closeAction, host, isTargetSource = true, sessionStrategy = currentSession.strategy) 
                                }
                                joinAll(job1, job2)
                            }
                            break
                        } catch (e: Exception) {
                            val msg = e.message?.lowercase(java.util.Locale.ROOT) ?: ""
                            val isDpiReset = e is java.net.SocketException && (msg.contains("reset") || msg.contains("broken pipe") || msg.contains("closed") || msg.contains("timeout"))
                            if (isDpiReset && retryCount < 2) {
                                retryCount++
                                ProxyStats.logRecovery("Transparent DPI Retry #$retryCount for $host...")
                                BypassConfig.recordFailureForHost(host, currentSession.strategy, isCritical = true)
                                try { currentTargetSocket.close() } catch(ex: Exception) {}
                                
                                currentSession = BypassConfig.resolveSessionConfigForHost(host)
                                val newAddrs = RobustResolver.resolve(host, vpnService, forceSecure = true)
                                val nextSocket = connectTargetWithHappyEyeballs(newAddrs, destPort, currentSession.strategy)
                                if (nextSocket != null) {
                                    currentTargetSocket = nextSocket
                                    continue
                                }
                            }
                            break
                        }
                    }
                    releaseBuffer(buffer)
                }
            } else if (requestLine.isNotEmpty()) {
                val parts = requestLine.split(" ")
                if (parts.size >= 2) {
                    var urlStr = parts[1]
                    var host: String? = null
                    var destPort = 80
                    
                    val headers = StringBuilder()
                    while (true) {
                        val header = readLine(clientInput)
                        if (header.isEmpty()) break
                        if (header.startsWith("host:", ignoreCase = true)) {
                            val h = header.substring(5).trim()
                            if (h.contains(":")) {
                                host = h.split(":")[0]
                                destPort = try { h.split(":")[1].toInt() } catch(e:Exception) { 80 }
                            } else {
                                host = h
                            }
                        } else {
                            headers.append(header).append("\r\n")
                        }
                    }

                    if (urlStr.startsWith("http://")) {
                        try {
                            val uri = java.net.URI(urlStr)
                            host = uri.host
                            destPort = if (uri.port != -1) uri.port else 80
                            urlStr = (uri.rawPath ?: "/") + (if(uri.rawQuery != null) "?" + uri.rawQuery else "")
                        } catch (e: Exception) {}
                    }

                    if (host != null) {
                        hostForStats = host
                        val session = BypassConfig.resolveSessionConfigForHost(host)
                        var resolvedAddresses = try {
                            RobustResolver.resolve(host, vpnService)
                        } catch (e: Exception) {
                            ProxyStats.addError()
                            throw e
                        }

                        if (resolvedAddresses.isEmpty()) {
                            throw java.net.UnknownHostException("No address found for $host")
                        }

                        // Happy Eyeballs: Parallel connect to speed up response
                        targetSocket = connectTargetWithHappyEyeballs(resolvedAddresses, destPort, session.strategy)

                        if (targetSocket == null) {
                            Log.w("PinkProxyServer", "HTTP connection Happy Eyeballs failed for $host. Retrying with secure DNS fallback...")
                            try {
                                val secureAddresses = RobustResolver.resolve(host, vpnService, forceSecure = true)
                                targetSocket = connectTargetWithHappyEyeballs(secureAddresses, destPort, session.strategy)
                            } catch (ex: Exception) {
                                Log.e("PinkProxyServer", "Secure DNS recovery failed for HTTP $host: ${ex.message}")
                            }
                        }

                        if (targetSocket == null) {
                            ProxyStats.addError()
                            throw java.net.ConnectException("Failed to connect to any resolved address for $host")
                        }
                        tuneSocket(targetSocket!!, session.strategy)
                        tuneSocket(clientSocket, session.strategy)
                        
                        val targetOutput = targetSocket!!.getOutputStream()
                        
                        val methodStr = when (session.strategy) {
                            BypassStrategy.HTTP_SPACE -> "${parts[0]} "
                            BypassStrategy.HTTP_TAB -> "${parts[0]}\t"
                            else -> parts[0]
                        }
                    val newRequestLine = "$methodStr ${if(urlStr.isEmpty()) "/" else urlStr} ${if (parts.size > 2) parts[2] else "HTTP/1.1"}\r\n"
                    
                    val hostWithPort = if (destPort == 80) host else "$host:$destPort"
                    val hostHeader = when(session.strategy) {
                        BypassStrategy.HOST_CASE -> "hOsT: $hostWithPort\r\n"
                        BypassStrategy.HOST_MIXED -> "HoSt: $hostWithPort\r\n"
                        BypassStrategy.HTTP_SPACE, BypassStrategy.HTTP_TAB -> " Host: $hostWithPort\r\n"
                        else -> "Host: $hostWithPort\r\n"
                    }
                    val bytes = (newRequestLine + hostHeader + headers.toString() + "\r\n").toByteArray()
                    
                    applyBypass(targetSocket, targetOutput, bytes, bytes.size, host, session, -1)
                    targetOutput.flush()
                    BypassConfig.recordSuccessForHost(host, session.strategy, vpnService)
                        
                    val closeAction = {
                        try { targetSocket?.close() } catch (e: Exception) {}
                        try { clientSocket.close() } catch (e: Exception) {}
                    }
 
                    coroutineScope {
                        val j1 = launch { proxyStream(clientInput, targetOutput, closeAction, host, isTargetSource = false, sessionStrategy = session.strategy) }
                        val j2 = launch { proxyStream(java.io.BufferedInputStream(targetSocket!!.getInputStream()), clientOutput, closeAction, host, isTargetSource = true, sessionStrategy = session.strategy) }
                        
                        joinAll(j1, j2)
                    }
                    } else {
                        clientSocket.close()
                    }
                } else {
                    clientSocket.close()
                }
            } else {
                clientSocket.close()
            }
        } catch (e: Exception) {
            val msg = e.message?.lowercase(java.util.Locale.ROOT) ?: ""
            val isClientClosed = e is java.net.SocketException && (msg.contains("closed") || msg.contains("broken pipe") || msg.contains("reset by peer"))
            val isClientTimeout = e is java.net.SocketTimeoutException
            if (!isClientClosed && !isClientTimeout) {
                val isCritical = msg.contains("youtube") || msg.contains("google") || msg.contains("telegram")
                BypassConfig.recordFailure(strategy = BypassConfig.strategy.value, isCritical = isCritical)
            }
            try { clientSocket.close() } catch (ex: Exception) {}
        } finally {
            try { targetSocket?.close() } catch (e: Exception) {}
            try { clientSocket.close() } catch (e: Exception) {}
            ProxyStats.removeConnection()
        }
    }

    private fun readLine(inputStream: java.io.InputStream): String {
        val sb = StringBuilder()
        var c: Int
        var count = 0
        while (count < 8192) {
            c = inputStream.read()
            if (c == -1 || c == '\n'.code) break
            if (c != '\r'.code) {
                sb.append(c.toChar())
                count++
            }
        }
        return sb.toString()
    }

    private suspend fun applyPacing(read: Int) {
        val rtt = BypassConfig.currentRttMs.value
        if (rtt > 20) {
            val pace = (read.toDouble() / 1500.0 * (rtt.toDouble() / 250.0)).toLong().coerceIn(0, 5)
            if (pace > 0) delay(pace)
        }
    }

    private suspend fun applyBypass(
        targetSocket: Socket?,
        targetOutput: OutputStream,
        buffer: ByteArray,
        read: Int,
        host: String,
        session: SessionConfig,
        sniPos: Int
    ) {
        applyPacing(read)
        val dna = BypassConfig.getDnaForHost(host)
        val f1 = dna.frag1
        val d1 = dna.delay1

        when (session.strategy) {
            BypassStrategy.WINDOW_SIZE -> {
                var pfd: android.os.ParcelFileDescriptor? = null
                try {
                    // Force tiny window to make DPI process traffic in tiny chunks
                    targetSocket?.apply {
                        tcpNoDelay = true
                        pfd = android.os.ParcelFileDescriptor.fromSocket(this)
                        val fd = pfd!!.fileDescriptor
                        // Set small buffers to trigger zero-window probes or tiny segments
                        android.system.Os.setsockoptInt(fd, android.system.OsConstants.SOL_SOCKET, android.system.OsConstants.SO_RCVBUF, 1024)
                        android.system.Os.setsockoptInt(fd, android.system.OsConstants.SOL_SOCKET, android.system.OsConstants.SO_SNDBUF, 1024)
                    }
                } catch (e: Exception) {
                } finally {
                    try { pfd?.close() } catch (e: Exception) {}
                }
                targetOutput.write(buffer, 0, read)
            }
            BypassStrategy.FAKE_PACKET -> {
                var pfd: android.os.ParcelFileDescriptor? = null
                try {
                    if (targetSocket != null) {
                        pfd = android.os.ParcelFileDescriptor.fromSocket(targetSocket)
                        val fd = pfd.fileDescriptor
                        val isIpv6 = targetSocket.inetAddress is java.net.Inet6Address
                        val proto = if (isIpv6) android.system.OsConstants.IPPROTO_IPV6 else android.system.OsConstants.IPPROTO_IP
                        val ttlOpt = if (isIpv6) android.system.OsConstants.IPV6_UNICAST_HOPS else android.system.OsConstants.IP_TTL
                        
                        val fakePayload = if (buffer.isNotEmpty() && buffer[0] == 0x16.toByte()) {
                            val fakeSNI = if (host.contains("google") || host.contains("youtube")) "www.microsoft.com" else "www.google.com"
                            FakePacketHelper.buildFakeClientHello(fakeSNI, ProxyStats.censorshipIntensity.value)
                        } else {
                            "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()
                        }
                        
                        // 1. Send first fake packet with primary TTL
                        android.system.Os.setsockoptInt(fd, proto, ttlOpt, session.fakeTtl)
                        targetOutput.write(fakePayload)
                        targetOutput.flush()
                        
                        // 2. Send second fake packet with TTL + 1 (expands DPI kill zone)
                        if (session.fakeTtl < 15) { // Prevent reaching real server
                            android.system.Os.setsockoptInt(fd, proto, ttlOpt, session.fakeTtl + 1)
                            targetOutput.write(fakePayload)
                            targetOutput.flush()
                        }
                        
                        delay(session.delay1)
                        
                        // 2. Restore TTL and send real packet
                        android.system.Os.setsockoptInt(fd, proto, ttlOpt, 64)
                        
                        // Use adaptive fragmentation for the real packet too if needed
                        val f1 = BypassConfig.getCurrentFragSize().coerceAtMost(read - 1).coerceAtLeast(1)
                        try {
                            withTimeout(7000) {
                                targetOutput.write(buffer, 0, f1)
                                targetOutput.flush()
                                delay(BypassConfig.getAdaptiveDelay2())
                                targetOutput.write(buffer, f1, read - f1)
                            }
                        } catch (e: Exception) {
                            BypassConfig.recordFailureForHost(host = host, strategy = session.strategy, isCritical = true)
                            throw e
                        }
                    } else {
                        targetOutput.write(buffer, 0, read)
                    }
                } catch (e: Exception) {
                    targetOutput.write(buffer, 0, read)
                } finally { 
                    try { pfd?.close() } catch (e: Exception) {} 
                }
            }
            BypassStrategy.TCP_OOB_DESYNC -> {
                val d1 = dna.delay1.coerceAtLeast(5)
                if (sniPos > 1) {
                    targetOutput.write(buffer, 0, sniPos)
                    targetOutput.flush()
                    delay(d1)
                    try {
                        targetSocket?.sendUrgentData((1..255).random())
                        delay(1)
                        targetSocket?.sendUrgentData((1..255).random())
                    } catch (e: Exception) {}
                    targetOutput.write(buffer, sniPos, read - sniPos)
                } else if (read > 1) {
                    val splitPoint = dna.frag1.coerceAtMost(read - 1).coerceAtLeast(1)
                    targetOutput.write(buffer, 0, splitPoint)
                    targetOutput.flush()
                    delay(d1)
                    try {
                        targetSocket?.sendUrgentData((1..255).random())
                    } catch (e: Exception) {}
                    targetOutput.write(buffer, splitPoint, read - splitPoint)
                } else {
                    targetOutput.write(buffer, 0, read)
                }
            }
            BypassStrategy.SNI_SPLIT, BypassStrategy.SNI_TRIPLE -> {
                val d1 = dna.delay1
                if (session.strategy == BypassStrategy.SNI_TRIPLE && sniPos > 2) {
                    targetOutput.write(buffer, 0, sniPos)
                    targetOutput.flush()
                    delay(d1)
                    val fragSize = dna.frag2.coerceAtMost(read - sniPos - 1).coerceAtLeast(1)
                    targetOutput.write(buffer, sniPos, fragSize)
                    targetOutput.flush()
                    delay(BypassConfig.getAdaptiveDelay2())
                    targetOutput.write(buffer, sniPos + fragSize, read - (sniPos + fragSize))
                } else if (sniPos > 1) {
                    targetOutput.write(buffer, 0, sniPos)
                    targetOutput.flush()
                    delay(d1)
                    targetOutput.write(buffer, sniPos, read - sniPos)
                } else {
                    val split = dna.frag1.coerceAtMost(read - 1).coerceAtLeast(1)
                    targetOutput.write(buffer, 0, split)
                    targetOutput.flush()
                    delay(d1)
                    targetOutput.write(buffer, split, read - split)
                }
            }
            BypassStrategy.FRAG_3_5 -> {
                val f1 = dna.frag1.coerceAtMost(read)
                val f2 = dna.frag2.coerceAtMost(read)
                if (f2 > f1) {
                    targetOutput.write(buffer, 0, f1)
                    targetOutput.flush()
                    delay(dna.delay1)
                    targetOutput.write(buffer, f1, f2 - f1)
                    targetOutput.flush()
                    delay(BypassConfig.getAdaptiveDelay2())
                    if (read > f2) targetOutput.write(buffer, f2, read - f2)
                } else if (f1 > 0 && f1 < read) {
                    targetOutput.write(buffer, 0, f1)
                    targetOutput.flush()
                    delay(dna.delay1)
                    targetOutput.write(buffer, f1, read - f1)
                } else {
                    targetOutput.write(buffer, 0, read)
                }
            }
            BypassStrategy.SNI_MANGLE -> {
                if (sniPos > 0) {
                    targetOutput.write(buffer, 0, sniPos)
                    targetOutput.flush()
                    delay(dna.delay1)
                    var currentPos = sniPos
                    val hostBytes = host.toByteArray()
                    val endPos = (sniPos + hostBytes.size).coerceAtMost(read)
                    while (currentPos < endPos) {
                        // Use DNA-based chunking for mangling
                        val chunk = if (dna.frag2 > 10) (1..2).random() else 1
                        val writeLen = chunk.coerceAtMost(endPos - currentPos)
                        targetOutput.write(buffer, currentPos, writeLen)
                        targetOutput.flush()
                        delay(2)
                        currentPos += writeLen
                    }
                    if (read > endPos) targetOutput.write(buffer, endPos, read - endPos)
                } else {
                    val split = dna.frag1.coerceAtMost(read - 1).coerceAtLeast(1)
                    targetOutput.write(buffer, 0, split)
                    targetOutput.flush()
                    delay(dna.delay1)
                    targetOutput.write(buffer, split, read - split)
                }
            }
            BypassStrategy.TLS_DIRTY -> {
                if (read > 5 && buffer[0] == 0x16.toByte()) {
                    // Inject a dummy TLS record to confuse DPI state machine
                    val intensity = ProxyStats.censorshipIntensity.value
                    val type = if (intensity > 60) 0x14.toByte() else 0x17.toByte() // Change Cipher Spec or Application Data
                    val version1 = 0x03.toByte()
                    val version2 = listOf(0x01.toByte(), 0x03.toByte(), 0x04.toByte()).random() // TLS 1.0, 1.2 or 1.3
                    
                    val dummyLen = if (intensity > 40) (1..5).random() else 0
                    val dirtyRecord = ByteArray(5 + dummyLen)
                    dirtyRecord[0] = type
                    dirtyRecord[1] = version1
                    dirtyRecord[2] = version2
                    dirtyRecord[3] = (dummyLen shr 8).toByte()
                    dirtyRecord[4] = (dummyLen and 0xFF).toByte()
                    
                    for (i in 0 until dummyLen) {
                        dirtyRecord[5 + i] = (1..255).random().toByte()
                    }
                    
                    targetOutput.write(dirtyRecord)
                    targetOutput.flush()
                    delay(session.delay1)
                    targetOutput.write(buffer, 0, read)
                } else if (read >= 5) {
                    targetOutput.write(buffer, 0, 1)
                    targetOutput.flush()
                    delay(session.delay1)
                    targetOutput.write(buffer, 1, 4)
                    targetOutput.flush()
                    delay(5)
                    targetOutput.write(buffer, 5, read - 5)
                } else {
                    targetOutput.write(buffer, 0, read)
                }
            }
            BypassStrategy.CHUNKY -> {
                var pos = 0
                while (pos < read) {
                    val chunkSize = if (Math.random() > 0.5) 1 else 2
                    val len = chunkSize.coerceAtMost(read - pos)
                    targetOutput.write(buffer, pos, len)
                    targetOutput.flush()
                    pos += len
                    if (pos < read) delay(session.delay1 / 5)
                }
            }
            BypassStrategy.RAND_SPLIT -> {
                if (read > 1) {
                    val f1 = BypassConfig.getCurrentFragSize().coerceAtMost(read - 1).coerceAtLeast(1)
                    targetOutput.write(buffer, 0, f1)
                    targetOutput.flush()
                    delay(BypassConfig.getAdaptiveDelay1())
                    targetOutput.write(buffer, f1, read - f1)
                } else targetOutput.write(buffer, 0, read)
            }
            BypassStrategy.HTTP_SPACE, BypassStrategy.HTTP_TAB -> {
                val spaceChar = if (session.strategy == BypassStrategy.HTTP_SPACE) 0x20.toByte() else 0x09.toByte()
                val methodEnd = buffer.indexOf(0x20.toByte()) // First space after method (GET, POST...)
                if (methodEnd > 0) {
                    targetOutput.write(buffer, 0, methodEnd)
                    targetOutput.write(spaceChar.toInt())
                    targetOutput.flush()
                    delay(session.delay1)
                    targetOutput.write(buffer, methodEnd + 1, read - (methodEnd + 1))
                } else {
                    targetOutput.write(buffer, 0, read)
                }
            }
            BypassStrategy.HOST_CASE, BypassStrategy.HOST_MIXED -> {
                // Find "Host: " and change case
                val hostHeader = "host: ".toByteArray()
                var found = -1
                for (i in 0 until read - hostHeader.size) {
                    var match = true
                    for (j in hostHeader.indices) {
                        val b1 = (buffer[i + j].toInt() and 0xFF).toChar().lowercaseChar()
                        val b2 = (hostHeader[j].toInt() and 0xFF).toChar().lowercaseChar()
                        if (b1 != b2) {
                            match = false
                            break
                        }
                    }
                    if (match) {
                        found = i
                        break
                    }
                }
                if (found != -1) {
                    targetOutput.write(buffer, 0, found)
                    val header = if (session.strategy == BypassStrategy.HOST_CASE) "hOsT: ".toByteArray() else "HoSt: ".toByteArray()
                    targetOutput.write(header)
                    targetOutput.write(buffer, found + hostHeader.size, read - (found + hostHeader.size))
                } else {
                    targetOutput.write(buffer, 0, read)
                }
            }
            BypassStrategy.HEADER_SPLIT -> {
                if (read > 5 && buffer[0] == 0x16.toByte() && buffer[1] == 0x03.toByte()) {
                    // TLS: Split after the 5-byte record header
                    targetOutput.write(buffer, 0, 5)
                    targetOutput.flush()
                    delay(session.delay1)
                    targetOutput.write(buffer, 5, read - 5)
                } else {
                    // HTTP: Split at the first colon
                    var colon = -1
                    for (i in 0 until read) {
                        if (buffer[i] == ':'.code.toByte()) {
                            colon = i
                            break
                        }
                    }
                    if (colon > 0 && colon < read - 1) {
                        targetOutput.write(buffer, 0, colon + 1)
                        targetOutput.flush()
                        delay(session.delay1)
                        targetOutput.write(buffer, colon + 1, read - (colon + 1))
                    } else {
                        targetOutput.write(buffer, 0, read)
                    }
                }
            }
            BypassStrategy.SLOW_SEND -> {
                // Send the first 100 bytes very slowly, 1-3 bytes at a time
                var pos = 0
                val slowLimit = 100.coerceAtMost(read)
                while (pos < slowLimit) {
                    val size = (1..3).random().coerceAtMost(slowLimit - pos)
                    targetOutput.write(buffer, pos, size)
                    targetOutput.flush()
                    pos += size
                    delay(session.delay1 / 2 + (0..20).random())
                }
                if (pos < read) {
                    targetOutput.write(buffer, pos, read - pos)
                    targetOutput.flush()
                }
            }
            BypassStrategy.OOB_DESYNC -> {
                if (read > 1) {
                    val f1 = session.frag1.coerceAtMost(read - 1).coerceAtLeast(1)
                    targetOutput.write(buffer, 0, f1)
                    try { targetSocket?.sendUrgentData('a'.code) } catch (e: Exception) {}
                    targetOutput.flush()
                    delay(session.delay1)
                    targetOutput.write(buffer, f1, read - f1)
                } else {
                    targetOutput.write(buffer, 0, read)
                }
            }
            BypassStrategy.TCP_ZERO_WINDOW -> {
                targetOutput.write(buffer, 0, read)
                targetOutput.flush()
                delay(session.delay1)
                var pfd: android.os.ParcelFileDescriptor? = null
                try {
                    pfd = android.os.ParcelFileDescriptor.fromSocket(targetSocket!!)
                    val fd = pfd.fileDescriptor
                    // Set receive buffer to 0 (or very small) to signal Zero Window
                    android.system.Os.setsockoptInt(fd, android.system.OsConstants.SOL_SOCKET, android.system.OsConstants.SO_RCVBUF, 1)
                    delay(BypassConfig.getAdaptiveDelay1() * 2)
                    // Restore buffer size
                    android.system.Os.setsockoptInt(fd, android.system.OsConstants.SOL_SOCKET, android.system.OsConstants.SO_RCVBUF, 131072)
                } catch (e: Exception) {
                } finally {
                    try { pfd?.close() } catch (e: Exception) {}
                }
            }
            BypassStrategy.TLS_PAD, BypassStrategy.TLS_GREASE -> {
                if (read > 10 && buffer[0] == 0x16.toByte() && host.isNotEmpty()) {
                    val newHello = FakePacketHelper.buildFakeClientHello(host, ProxyStats.censorshipIntensity.value)
                    val split = (newHello.size / 2).coerceAtLeast(1)
                    targetOutput.write(newHello, 0, split)
                    targetOutput.flush()
                    delay(session.delay1)
                    targetOutput.write(newHello, split, newHello.size - split)
                } else {
                    targetOutput.write(buffer, 0, read)
                }
            }
            BypassStrategy.GHOST_PACKETS -> {
                targetOutput.write(buffer, 0, read)
                targetOutput.flush()
                
                // Asynchronous ghosting to avoid blocking the main proxy loop
                if (read > 5 && buffer[0] == 0x16.toByte() && vpnService != null) {
                    kotlinx.coroutines.CoroutineScope(proxyDispatcher).launch {
                        repeat((2..5).random()) {
                            delay((400..1200).random().toLong())
                            try {
                                if (targetSocket?.isClosed == false) {
                                    val junk = ByteArray((10..30).random()) { (0..255).random().toByte() }
                                    val ghost = ByteArray(5 + junk.size)
                                    ghost[0] = listOf(0x15, 0x16, 0x17).random().toByte() // Alert, Handshake or AppData
                                    ghost[1] = 0x03
                                    ghost[2] = 0x03
                                    ghost[3] = (junk.size shr 8).toByte()
                                    ghost[4] = (junk.size and 0xFF).toByte()
                                    System.arraycopy(junk, 0, ghost, 5, junk.size)
                                    
                                    targetOutput.write(ghost)
                                    targetOutput.flush()
                                }
                            } catch (e: Exception) {}
                        }
                    }
                }
            }
            else -> {
                targetOutput.write(buffer, 0, read)
            }
        }
        targetOutput.flush()
    }

    private suspend fun proxyStream(
        input: java.io.InputStream,
        output: java.io.OutputStream,
        onSocketError: () -> Unit,
        host: String? = null,
        isTargetSource: Boolean = false,
        sessionStrategy: BypassStrategy? = null
    ) {
        val startTime = System.currentTimeMillis()
        var recordedLongSuccess = false
        var recordedShortSuccess = false
        var totalRead = 0L
        var lastActivity = System.currentTimeMillis()
        
        withContext(proxyDispatcher) {
            // Dynamic Buffer Sizing based on RTT
            val rtt = BypassConfig.currentRttMs.value
            val bufferSize = when {
                rtt < 80 -> 65536  // 64KB for fast networks
                rtt < 200 -> 32768 // 32KB
                else -> 16384      // 16KB for slow/congested
            }
            val buffer = getBuffer(bufferSize)
            var isThrottled = false
            
            // Watchdog for stalled connections (Traffic Profiler)
            val watchdog = launch {
                while (isActive) {
                    delay(5000)
                    val now = System.currentTimeMillis()
                    
                    // Stalling Detection
                    if (now - lastActivity > 10000 && totalRead > 0) {
                        if (host != null && BypassConfig.isHostCensored(host)) {
                            ProxyStats.logRecovery("PROFILER: Connection to $host STALLED. Mutating DNA.")
                            BypassConfig.mutateDnaForHost(host)
                            BypassConfig.recordFailureForHost(host, sessionStrategy ?: BypassConfig.strategy.value, isCritical = false, context = vpnService)
                        }
                        onSocketError() // Force close
                        break
                    }

                    // Throttling Detection (Speed < 50KB/s after 100KB transferred)
                    if (totalRead > 1024 * 100 && !isThrottled) {
                        val duration = (now - startTime) / 1000.0
                        val speedKbps = (totalRead / 1024.0) / duration
                        if (speedKbps < 50) {
                            isThrottled = true
                            if (host != null) {
                                ProxyStats.logRecovery("PROFILER: $host Throttled (${speedKbps.toInt()} KB/s). Mutating DNA.")
                                BypassConfig.mutateDnaForHost(host)
                            }
                        }
                    }
                }
            }

            try {
                while (isActive) {
                    val read = try { 
                        input.read(buffer) 
                    } catch (e: java.net.SocketTimeoutException) {
                        break 
                    } catch (e: java.net.SocketException) {
                        if (e.message?.contains("reset", ignoreCase = true) == true) {
                            val activeStrat = sessionStrategy ?: BypassConfig.strategy.value
                            if (host != null) {
                                BypassConfig.recordFailureForHost(host = host, strategy = activeStrat, isCritical = true, context = vpnService)
                            }
                        }
                        -1
                    } catch (e: Exception) { 
                        if (isTargetSource && System.currentTimeMillis() - startTime < 3000 && totalRead == 0L) {
                            val activeStrat = sessionStrategy ?: BypassConfig.strategy.value
                            if (host != null) {
                                BypassConfig.recordFailureForHost(host = host, strategy = activeStrat, isCritical = true, context = vpnService)
                            } else {
                                BypassConfig.recordFailure(strategy = activeStrat, isCritical = true, context = vpnService)
                            }
                        }
                        -1 
                    }
                    
                    if (read < 0) break
                    
                    if (read > 0) {
                        lastActivity = System.currentTimeMillis()
                        totalRead += read
                        ProxyStats.addBytes(read.toLong())
                        
                        // Adaptive Fragmenting & MSS Clamping Emulation
                        val censorship = ProxyStats.censorshipIntensity.value
                        val isCensored = host != null && BypassConfig.isHostCensored(host)
                        val shouldFrag = (censorship > 40 && totalRead < 524288) || (isCensored && totalRead < 1048576)
                        
                        if (shouldFrag && read > 1 && !isTargetSource) {
                            // MSS Clamping: limit segment size to 1300 if censored/throttled
                            val maxSegment = if (isThrottled || (isCensored && (0..10).random() > 5)) 1300 else read
                            
                            if (maxSegment < read) {
                                var offset = 0
                                while (offset < read) {
                                    val chunk = (read - offset).coerceAtMost(maxSegment)
                                    val f1 = (BypassConfig.getCurrentFragSize() + (0..1).random()).coerceAtMost(chunk - 1).coerceAtLeast(1)
                                    output.write(buffer, offset, f1)
                                    output.flush()
                                    delay((1..3).random().toLong())
                                    output.write(buffer, offset + f1, chunk - f1)
                                    offset += chunk
                                    output.flush()
                                }
                            } else {
                                val f1 = (BypassConfig.getCurrentFragSize() + (0..1).random()).coerceAtMost(read - 1).coerceAtLeast(1)
                                output.write(buffer, 0, f1)
                                output.flush()
                                if (censorship > 70) delay((2..8).random().toLong())
                                output.write(buffer, f1, read - f1)
                            }
                        } else {
                            output.write(buffer, 0, read)
                        }
                        
                        // Smart Flush: flush immediately only for small packets, or if there is no more data currently available to read
                        if (read < 1500 || totalRead < 262144 || input.available() == 0) {
                            // Add tiny jitter for better desync (0-5ms)
                            if (totalRead < 1048576 && (0..10).random() > 7) {
                                delay((0..5).random().toLong())
                            }
                            output.flush()
                        }
                    }

                    // Success reporting logic
                    if (!recordedShortSuccess && (System.currentTimeMillis() - startTime > 2000 || totalRead > 16384)) {
                        recordedShortSuccess = true
                        ProxyStats.recordGlobalSuccess()
                        val activeStrat = sessionStrategy ?: BypassConfig.strategy.value
                        if (host != null) {
                            BypassConfig.recordSuccessForHost(host, activeStrat, context = vpnService)
                        } else {
                            ProxyStats.recordStrategySuccess(activeStrat, context = vpnService)
                        }
                    }
                    
                    if (!recordedLongSuccess && (System.currentTimeMillis() - startTime > 15000 || totalRead > 1024 * 1024)) {
                        recordedLongSuccess = true
                        BypassConfig.adjustFragmentation(true)
                        val activeStrat = sessionStrategy ?: BypassConfig.strategy.value
                        if (host != null) {
                            BypassConfig.recordSuccessForHost(host, activeStrat, context = vpnService)
                        } else {
                            BypassConfig.recordSuccess(activeStrat, context = vpnService)
                        }
                    }
                }
            } catch (e: Exception) {
                val msg = e.message?.lowercase(java.util.Locale.ROOT) ?: ""
                val isNormalDisconnect = e is java.net.SocketException && (msg.contains("closed") || msg.contains("broken pipe") || msg.contains("reset by peer"))
                if (!isNormalDisconnect) {
                    ProxyStats.addError()
                }
            } finally {
                watchdog.cancel()
                releaseBuffer(buffer)
                try { output.flush() } catch (e: Exception) {}
                onSocketError()
            }
        }
    }

    private suspend fun handleSocks5Client(
        clientSocket: Socket,
        clientInput: java.io.BufferedInputStream,
        clientOutput: java.io.OutputStream
    ) {
        var targetSocket: Socket? = null
        var host = ""
        try {
            // 1. Read authentication methods
            val numMethods = clientInput.read()
            if (numMethods == -1) return
            val methods = ByteArray(numMethods)
            var readMethods = 0
            while (readMethods < numMethods) {
                val r = clientInput.read(methods, readMethods, numMethods - readMethods)
                if (r == -1) return
                readMethods += r
            }
            
            // Send selected auth method: No Auth (0x00)
            clientOutput.write(byteArrayOf(0x05, 0x00))
            clientOutput.flush()
            
            // 2. Read request header
            val version = clientInput.read()
            if (version != 0x05) return
            val command = clientInput.read()
            val reserved = clientInput.read()
            val addressType = clientInput.read()
            
            if (command == 0x03) { // UDP ASSOCIATE
                handleSocks5UdpAssociate(clientSocket, clientInput, clientOutput, addressType)
                return
            }
            
            if (command != 0x01) { // CONNECT command only
                // Command not supported reply
                clientOutput.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                clientOutput.flush()
                return
            }
            
            var destPort = 0
            
            when (addressType) {
                0x01 -> { // IPv4
                    val ipv4 = ByteArray(4)
                    var readIp = 0
                    while (readIp < 4) {
                        val r = clientInput.read(ipv4, readIp, 4 - readIp)
                        if (r == -1) return
                        readIp += r
                    }
                    host = java.net.InetAddress.getByAddress(ipv4).hostAddress ?: ""
                }
                0x03 -> { // Domain Name
                    val length = clientInput.read()
                    if (length == -1) return
                    val domainBytes = ByteArray(length)
                    var readDomain = 0
                    while (readDomain < length) {
                        val r = clientInput.read(domainBytes, readDomain, length - readDomain)
                        if (r == -1) return
                        readDomain += r
                    }
                    host = String(domainBytes, java.nio.charset.StandardCharsets.US_ASCII)
                }
                0x04 -> { // IPv6
                    val ipv6 = ByteArray(16)
                    var readIp = 0
                    while (readIp < 16) {
                        val r = clientInput.read(ipv6, readIp, 16 - readIp)
                        if (r == -1) return
                        readIp += r
                    }
                    host = java.net.InetAddress.getByAddress(ipv6).hostAddress ?: ""
                }
                else -> {
                    // Address type not supported reply
                    clientOutput.write(byteArrayOf(0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    clientOutput.flush()
                    return
                }
            }
            
            val session = BypassConfig.resolveSessionConfigForHost(host)
            ProxyStats.logTraffic(host, session.strategy.name)
            
            val port1 = clientInput.read()
            val port2 = clientInput.read()
            if (port1 == -1 || port2 == -1) return
            destPort = (port1 shl 8) or port2
            
            // 3. Resolve destination
            var resolvedAddresses = try {
                RobustResolver.resolve(host, vpnService)
            } catch (e: Exception) {
                ProxyStats.addError()
                BypassConfig.recordFailureForHost(host = host, strategy = session.strategy, isCritical = true, context = vpnService)
                // Host unreachable reply
                clientOutput.write(byteArrayOf(0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                clientOutput.flush()
                return
            }
            
            if (resolvedAddresses.isEmpty()) {
                clientOutput.write(byteArrayOf(0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                clientOutput.flush()
                return
            }
            
            targetSocket = connectTargetWithHappyEyeballs(resolvedAddresses, destPort, session.strategy)
            
            if (targetSocket == null) {
                Log.w("PinkProxyServer", "SOCKS5 connection to $host failed. Retrying with secure DNS fallback...")
                try {
                    val secureAddresses = RobustResolver.resolve(host, vpnService, forceSecure = true)
                    targetSocket = connectTargetWithHappyEyeballs(secureAddresses, destPort, session.strategy)
                } catch (ex: Exception) {
                    Log.e("PinkProxyServer", "Secure DNS recovery failed for SOCKS5 $host: ${ex.message}")
                }
            }
            
            if (targetSocket == null) {
                ProxyStats.addError()
                BypassConfig.recordFailureForHost(host = host, strategy = session.strategy, isCritical = true, context = vpnService)
                // Connection refused reply
                clientOutput.write(byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                clientOutput.flush()
                return
            }
            
            tuneSocket(targetSocket!!, session.strategy)
            tuneSocket(clientSocket, session.strategy)
            
            // Send success reply
            clientOutput.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            clientOutput.flush()
            
            // 4. Read the first payload (usually ClientHello) from the client and apply bypass
            val buffer = getBuffer()
            clientSocket.soTimeout = 7000
            val read = try {
                clientInput.read(buffer)
            } catch (e: Exception) {
                -1
            }
            clientSocket.soTimeout = 300000
            
            if (read > 0) {
                ProxyStats.addBytes(read.toLong())
                val targetOutput = targetSocket!!.getOutputStream()
                
                // If it is a TLS Handshake, desynchronize it!
                if (read > 40 && buffer[0] == 0x16.toByte() && buffer[1] == 0x03.toByte()) {
                    var sniPos = TlsParser.findSniOffset(buffer, read)
                    if (sniPos == -1) {
                        val hostBytes = host.toByteArray()
                        if (hostBytes.size > 3) {
                            for (i in 30 until (read - hostBytes.size).coerceAtMost(1500)) {
                                var match = true
                                for (j in hostBytes.indices) {
                                    val b1 = buffer[i + j]
                                    val b2 = hostBytes[j]
                                    if (b1 != b2) {
                                        val c1 = (b1.toInt() and 0xFF).toChar().lowercaseChar()
                                        val c2 = (b2.toInt() and 0xFF).toChar().lowercaseChar()
                                        if (c1 != c2) {
                                            match = false
                                            break
                                        }
                                    }
                                }
                                if (match) {
                                    sniPos = i
                                    break
                                }
                            }
                        }
                    }
                    
                    applyBypass(targetSocket, targetOutput, buffer, read, host, session, sniPos)
                    targetOutput.flush()
                } else if (read > 2) {
                    targetOutput.write(buffer, 0, 2)
                    targetOutput.flush()
                    delay(10)
                    targetOutput.write(buffer, 2, read - 2)
                    targetOutput.flush()
                } else {
                    targetOutput.write(buffer, 0, read)
                    targetOutput.flush()
                }
                releaseBuffer(buffer)
                
                val closeAction = {
                    try { targetSocket?.close() } catch (e: Exception) {}
                    try { clientSocket.close() } catch (e: Exception) {}
                }
                
                coroutineScope {
                    val j1 = launch { proxyStream(clientInput, targetOutput, closeAction, host, isTargetSource = false, sessionStrategy = session.strategy) }
                    val j2 = launch { proxyStream(java.io.BufferedInputStream(targetSocket!!.getInputStream()), clientOutput, closeAction, host, isTargetSource = true, sessionStrategy = session.strategy) }
                    joinAll(j1, j2)
                }
            } else {
                releaseBuffer(buffer)
                clientSocket.close()
            }
        } catch (e: Exception) {
            val msg = e.message?.lowercase(java.util.Locale.ROOT) ?: ""
            val isClientClosed = e is java.net.SocketException && (msg.contains("closed") || msg.contains("broken pipe") || msg.contains("reset by peer"))
            val isClientTimeout = e is java.net.SocketTimeoutException
            if (!isClientClosed && !isClientTimeout) {
                val isCritical = msg.contains("youtube") || msg.contains("google") || msg.contains("telegram")
                val activeStrat = if (host.isNotEmpty()) BypassConfig.resolveStrategyForHost(host) else BypassConfig.strategy.value
                if (host.isNotEmpty()) {
                    BypassConfig.recordFailureForHost(host = host, strategy = activeStrat, isCritical = isCritical, context = vpnService)
                } else {
                    BypassConfig.recordFailure(strategy = activeStrat, isCritical = isCritical, context = vpnService)
                }
            }
            try { clientSocket.close() } catch (ex: Exception) {}
        } finally {
            try { targetSocket?.close() } catch (e: Exception) {}
            try { clientSocket.close() } catch (e: Exception) {}
            ProxyStats.removeConnection()
        }
    }

    private class ParsedUdpHeader(val host: String, val port: Int, val payload: ByteArray)

    private fun parseSocks5UdpHeader(data: ByteArray, length: Int): ParsedUdpHeader? {
        if (length < 10) return null
        val frag = data[2].toInt() and 0xFF
        if (frag != 0) return null
        val atyp = data[3].toInt() and 0xFF
        
        var offset = 4
        var host = ""
        when (atyp) {
            0x01 -> { // IPv4
                if (length < offset + 4 + 2) return null
                val ipBytes = ByteArray(4)
                System.arraycopy(data, offset, ipBytes, 0, 4)
                host = java.net.InetAddress.getByAddress(ipBytes).hostAddress ?: ""
                offset += 4
            }
            0x03 -> { // Domain Name
                val len = data[offset].toInt() and 0xFF
                offset += 1
                if (length < offset + len + 2) return null
                host = String(data, offset, len, java.nio.charset.StandardCharsets.US_ASCII)
                offset += len
            }
            0x04 -> { // IPv6
                if (length < offset + 16 + 2) return null
                val ipBytes = ByteArray(16)
                System.arraycopy(data, offset, ipBytes, 0, 16)
                host = java.net.InetAddress.getByAddress(ipBytes).hostAddress ?: ""
                offset += 16
            }
            else -> return null
        }
        val port = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
        offset += 2
        
        val payloadLen = length - offset
        if (payloadLen <= 0) return null
        
        val payload = ByteArray(payloadLen)
        System.arraycopy(data, offset, payload, 0, payloadLen)
        return ParsedUdpHeader(host, port, payload)
    }

    private fun buildSocks5UdpResponse(remoteIp: String, remotePort: Int, payload: ByteArray): ByteArray {
        val ipParts = remoteIp.split(".")
        val isIpv4 = ipParts.size == 4 && ipParts.all { it.toIntOrNull() in 0..255 }
        
        val headerSize = if (isIpv4) 10 else 4 + 1 + remoteIp.length + 2
        val response = ByteArray(headerSize + payload.size)
        response[0] = 0x00
        response[1] = 0x00
        response[2] = 0x00 // FRAG
        if (isIpv4) {
            response[3] = 0x01 // ATYP IPv4
            for (i in 0 until 4) {
                try {
                    response[4 + i] = ipParts[i].toInt().toByte()
                } catch (e: Exception) {
                    response[4 + i] = 0
                }
            }
            response[8] = ((remotePort shr 8) and 0xFF).toByte()
            response[9] = (remotePort and 0xFF).toByte()
            System.arraycopy(payload, 0, response, 10, payload.size)
        } else {
            response[3] = 0x03 // ATYP Domain
            response[4] = remoteIp.length.toByte()
            val domainBytes = remoteIp.toByteArray(java.nio.charset.StandardCharsets.US_ASCII)
            System.arraycopy(domainBytes, 0, response, 5, domainBytes.size)
            val offset = 5 + domainBytes.size
            response[offset] = ((remotePort shr 8) and 0xFF).toByte()
            response[offset + 1] = (remotePort and 0xFF).toByte()
            System.arraycopy(payload, 0, response, offset + 2, payload.size)
        }
        return response
    }

    private suspend fun handleSocks5UdpAssociate(
        clientSocket: Socket,
        clientInput: java.io.BufferedInputStream,
        clientOutput: java.io.OutputStream,
        addressType: Int
    ) {
        // Read client bind address if specified
        when (addressType) {
            0x01 -> { // IPv4
                val ipv4 = ByteArray(4)
                var readIp = 0
                while (readIp < 4) {
                    val r = clientInput.read(ipv4, readIp, 4 - readIp)
                    if (r == -1) return
                    readIp += r
                }
            }
            0x03 -> { // Domain
                val length = clientInput.read()
                if (length == -1) return
                val domainBytes = ByteArray(length)
                var readDomain = 0
                while (readDomain < length) {
                    val r = clientInput.read(domainBytes, readDomain, length - readDomain)
                    if (r == -1) return
                    readDomain += r
                }
            }
            0x04 -> { // IPv6
                val ipv6 = ByteArray(16)
                var readIp = 0
                while (readIp < 16) {
                    val r = clientInput.read(ipv6, readIp, 16 - readIp)
                    if (r == -1) return
                    readIp += r
                }
            }
        }
        // Read client bind port (2 bytes)
        val p1 = clientInput.read()
        val p2 = clientInput.read()
        if (p1 == -1 || p2 == -1) return

        var localUdpSocket: java.net.DatagramSocket? = null
        val remoteSockets = ConcurrentHashMap<String, java.net.DatagramSocket>()
        
        try {
            // Bind to loopback, dynamic port
            localUdpSocket = java.net.DatagramSocket(0, java.net.InetAddress.getByName("127.0.0.1"))
            val localPort = localUdpSocket.localPort
            
            // Send success reply
            val portByte1 = (localPort shr 8) and 0xFF
            val portByte2 = localPort and 0xFF
            val reply = byteArrayOf(
                0x05, // Version
                0x00, // Success
                0x00, // Reserved
                0x01, // IPv4 BND.ADDR (always IPv4 127.0.0.1 for local connection)
                127, 0, 0, 1,
                portByte1.toByte(),
                portByte2.toByte()
            )
            clientOutput.write(reply)
            clientOutput.flush()
            
            // Start UDP Relayer Coroutine
            val udpJob = scope.launch(proxyDispatcher) {
                val rxBuffer = ByteArray(65535)
                while (isActive && !localUdpSocket!!.isClosed) {
                    try {
                        val packet = java.net.DatagramPacket(rxBuffer, rxBuffer.size)
                        localUdpSocket.receive(packet)
                        val clientAddr = packet.address
                        val clientPort = packet.port
                        val length = packet.length
                        val data = packet.data.copyOf(length)
                        
                        launch {
                            try {
                                val parsed = parseSocks5UdpHeader(data, length) ?: return@launch
                                val sessionKey = "${clientAddr.hostAddress}:$clientPort -> ${parsed.host}:${parsed.port}"
                                
                                var remoteSocket = remoteSockets[sessionKey]
                                if (remoteSocket == null || remoteSocket.isClosed) {
                                    remoteSocket = java.net.DatagramSocket()
                                    vpnService.protect(remoteSocket)
                                    remoteSockets[sessionKey] = remoteSocket
                                    
                                    // Start listening loop for this remote socket
                                    launch {
                                        val remoteBuffer = ByteArray(65535)
                                        while (!remoteSocket.isClosed && !localUdpSocket!!.isClosed) {
                                            try {
                                                val rPacket = java.net.DatagramPacket(remoteBuffer, remoteBuffer.size)
                                                remoteSocket.receive(rPacket)
                                                val replyLen = rPacket.length
                                                val replyData = rPacket.data.copyOf(replyLen)
                                                val senderIp = rPacket.address.hostAddress ?: ""
                                                val senderPort = rPacket.port
                                                
                                                val socksHeader = buildSocks5UdpResponse(senderIp, senderPort, replyData)
                                                val outPacket = java.net.DatagramPacket(socksHeader, socksHeader.size, clientAddr, clientPort)
                                                localUdpSocket.send(outPacket)
                                            } catch (e: Exception) {
                                                break
                                            }
                                        }
                                        try { remoteSocket.close() } catch(e: Exception) {}
                                        remoteSockets.remove(sessionKey)
                                    }
                                }
                                
                                val targetAddrs = RobustResolver.resolve(parsed.host, vpnService)
                                if (targetAddrs.isNotEmpty()) {
                                    val targetIp = targetAddrs.first()
                                    val payload = parsed.payload
                                    
                                    // UDP DPI Bypass: Inject fake UDP packet with low TTL
                                    if (payload.size > 10 && BypassConfig.strategy.value == BypassStrategy.FAKE_PACKET) {
                                        try {
                                            val pfd = android.os.ParcelFileDescriptor.fromDatagramSocket(remoteSocket)
                                            val fd = pfd.fileDescriptor
                                            val isIpv6 = targetIp is java.net.Inet6Address
                                            val proto = if (isIpv6) android.system.OsConstants.IPPROTO_IPV6 else android.system.OsConstants.IPPROTO_IP
                                            val ttlOpt = if (isIpv6) android.system.OsConstants.IPV6_UNICAST_HOPS else android.system.OsConstants.IP_TTL
                                            
                                            android.system.Os.setsockoptInt(fd, proto, ttlOpt, BypassConfig.fakeTtl)
                                            val fakePayload = ByteArray(payload.size) { (1..255).random().toByte() }
                                            remoteSocket.send(java.net.DatagramPacket(fakePayload, fakePayload.size, targetIp, parsed.port))
                                            
                                            android.system.Os.setsockoptInt(fd, proto, ttlOpt, 64)
                                            pfd.close()
                                        } catch (e: Exception) {}
                                    }
                                    
                                    remoteSocket.send(java.net.DatagramPacket(payload, payload.size, targetIp, parsed.port))
                                    ProxyStats.addBytes(payload.size.toLong())
                                }
                            } catch (e: Exception) {
                                Log.e("PinkProxyServer", "UDP proxy packet routing failed", e)
                            }
                        }
                    } catch (e: Exception) {
                        break
                    }
                }
            }
            
            // Wait for client TCP socket to close
            val tempBuffer = ByteArray(1)
            while (clientSocket.isConnected && !clientSocket.isClosed) {
                val r = clientSocket.getInputStream().read(tempBuffer)
                if (r == -1) break
            }
            udpJob.cancel()
        } catch (e: Exception) {
            Log.e("PinkProxyServer", "SOCKS5 UDP Associate session error", e)
            try {
                // Command failed reply
                clientOutput.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                clientOutput.flush()
            } catch (ex: Exception) {}
        } finally {
            try { localUdpSocket?.close() } catch (e: Exception) {}
            remoteSockets.values.forEach {
                try { it.close() } catch (e: Exception) {}
            }
            remoteSockets.clear()
            try { clientSocket.close() } catch (e: Exception) {}
        }
    }

    private fun startNetworkObserver() {
        val connectivityManager = vpnService.getSystemService(android.content.Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
        val request = android.net.NetworkRequest.Builder()
            .addCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
            
        connectivityManager.registerNetworkCallback(request, object : android.net.ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: android.net.Network) {
                val caps = connectivityManager.getNetworkCapabilities(network)
                val type = when {
                    caps?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) == true -> NetworkType.WIFI
                    caps?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR) == true -> NetworkType.MOBILE
                    else -> NetworkType.UNKNOWN
                }
                
                if (BypassConfig.currentNetworkType.value != type) {
                    BypassConfig.updateNetworkType(type)
                    RobustResolver.clearCache()
                    Log.i("PinkProxyServer", "Network changed to $type. Flushed DNS cache.")
                }
            }
        })
    }

    private fun startProbingTask() {
        scope.launch {
            while (isActive) {
                val powerManager = vpnService.getSystemService(android.content.Context.POWER_SERVICE) as android.os.PowerManager
                val isPowerSave = powerManager.isPowerSaveMode
                val waitTime = if (isPowerSave) 600000L else 300000L // 10m vs 5m
                delay(waitTime)
                
                if (ProxyStats.getActiveConnections() == 0) {
                    probeStrategies()
                }
            }
        }
    }

    fun testInitialStrategies() {
        scope.launch {
            try {
                ProxyStats.logRecovery("Starting background strategy probe...")
                probeStrategies()
            } catch (e: Exception) {}
        }
    }

    private suspend fun probeStrategies() {
        val testHosts = listOf("www.instagram.com", "www.youtube.com", "t.me", "www.facebook.com")
        val strategies = BypassStrategy.entries.filter { it != BypassStrategy.DIRECT }.shuffled().take(2)
        
        for (strategy in strategies) {
            val testHost = testHosts.random()
            try {
                val ips = try { RobustResolver.resolve(testHost, vpnService) } catch (e: Exception) { emptyList() }
                if (ips.isNotEmpty()) {
                    withTimeout(5000) {
                        val socket = Socket()
                        socket.connect(InetSocketAddress(ips.first(), 443), 3000)
                        tuneSocket(socket, strategy)
                        val output = socket.getOutputStream()
                        val input = socket.getInputStream()
                        
                        val sni = FakePacketHelper.buildFakeClientHello(testHost, ProxyStats.censorshipIntensity.value)
                        val session = BypassConfig.getSessionConfig(testHost, strategy, 50)
                        applyBypass(socket, output, sni, sni.size, testHost, session, 0)
                        output.flush()
                        
                        val buffer = ByteArray(1024)
                        val read = input.read(buffer)
                        if (read > 0) {
                            BypassConfig.recordSuccessForHost(testHost, strategy, vpnService)
                        }
                        socket.close()
                    }
                }
            } catch (e: Exception) {}
            delay(2000)
        }
    }

    private suspend fun connectTargetWithHappyEyeballs(
        resolvedAddresses: List<java.net.InetAddress>,
        destPort: Int,
        strategy: BypassStrategy
    ): Socket? = kotlinx.coroutines.withContext(proxyDispatcher) {
        try {
            kotlinx.coroutines.withTimeout(12000) {
                val socketChannel = kotlinx.coroutines.channels.Channel<Socket>(1)
                val ipv6Addresses = resolvedAddresses.filter { it is java.net.Inet6Address }
                val ipv4Addresses = resolvedAddresses.filter { it is java.net.Inet4Address }
                
                // Interleave IPv6 and IPv4, prioritizing IPv6 as per RFC 8305 for faster dual-stack handshakes
                val targetAddresses = mutableListOf<java.net.InetAddress>()
                val maxLen = maxOf(ipv6Addresses.size, ipv4Addresses.size)
                for (i in 0 until maxLen) {
                    if (i < ipv6Addresses.size) targetAddresses.add(ipv6Addresses[i])
                    if (i < ipv4Addresses.size) targetAddresses.add(ipv4Addresses[i])
                }
                
                if (targetAddresses.isEmpty()) return@withTimeout null
                
                val connectionJobs = targetAddresses.mapIndexed { index, address ->
                    launch {
                        if (address.isLoopbackAddress) return@launch
                        delay(index * 250L) // Staggered parallel start (Happy Eyeballs RFC 8305)
                        val s = Socket()
                        vpnService.protect(s)
                        try {
                            val start = System.currentTimeMillis()
                            s.connect(java.net.InetSocketAddress(address, destPort), 7000)
                            val rtt = System.currentTimeMillis() - start
                            BypassConfig.updateRtt(rtt)
                            tuneSocket(s, strategy)
                            if (!socketChannel.trySend(s).isSuccess) {
                                try { s.close() } catch (e: Exception) {}
                            }
                        } catch (e: Exception) {
                            try { s.close() } catch (e: Exception) {}
                        }
                    }
                }
                try {
                    val winner = socketChannel.receive()
                    connectionJobs.forEach { it.cancel() }
                    winner
                } catch (e: Exception) {
                    connectionJobs.forEach { it.cancel() }
                    null
                }
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun tuneSocket(socket: Socket?, strategy: BypassStrategy? = null) {
        try {
            socket?.apply {
                tcpNoDelay = true
                keepAlive = true
                soTimeout = 30000
                
                // If WINDOW_SIZE strategy is active, clamp receive window to trigger tiny segments
                if (strategy == BypassStrategy.WINDOW_SIZE) {
                    sendBufferSize = 1500
                    receiveBufferSize = 1500
                } else {
                    val speed = ProxyStats.speedBytesPerSecond.value.coerceAtLeast(1024L)
                    val rttSec = (BypassConfig.currentRttMs.value.toDouble() / 1000.0).coerceIn(0.01, 2.0)
                    val bdp = (speed * rttSec).toLong()
                    // Minimum 128KB, maximum 1MB, dynamic sizing based on current performance
                    val optimalSize = bdp.coerceIn(128 * 1024L, 1024 * 1024L).toInt()
                    
                    sendBufferSize = optimalSize
                    receiveBufferSize = optimalSize
                }
                
                var pfd: android.os.ParcelFileDescriptor? = null
                try {
                    pfd = android.os.ParcelFileDescriptor.fromSocket(this)
                    val fd = pfd.fileDescriptor
                    // TCP_NODELAY
                    android.system.Os.setsockoptInt(fd, android.system.OsConstants.IPPROTO_TCP, android.system.OsConstants.TCP_NODELAY, 1)
                    
                    // TCP_MAXSEG (MSS clamping) to prevent carrier fragmentation/DPI reconstruction
                    val optimalMss = if (BypassConfig.currentNetworkType.value == NetworkType.WIFI) 1220 else 1160
                    try { android.system.Os.setsockoptInt(fd, android.system.OsConstants.IPPROTO_TCP, 2, optimalMss) } catch(e: Exception) {}

                    // TCP_USER_TIMEOUT (12 seconds)
                    try { android.system.Os.setsockoptInt(fd, android.system.OsConstants.IPPROTO_TCP, 18, 12000) } catch(e: Exception) {}
                    
                    if (strategy == BypassStrategy.WINDOW_SIZE) {
                        try { android.system.Os.setsockoptInt(fd, android.system.OsConstants.SOL_SOCKET, android.system.OsConstants.SO_RCVBUF, 1500) } catch(e: Exception) {}
                        try { android.system.Os.setsockoptInt(fd, android.system.OsConstants.SOL_SOCKET, android.system.OsConstants.SO_SNDBUF, 1500) } catch(e: Exception) {}
                    } else {
                        // TCP_KEEPALIVE options
                        try { android.system.Os.setsockoptInt(fd, android.system.OsConstants.IPPROTO_TCP, 4, 60) } catch(e: Exception) {} // TCP_KEEPIDLE
                        try { android.system.Os.setsockoptInt(fd, android.system.OsConstants.IPPROTO_TCP, 5, 10) } catch(e: Exception) {} // TCP_KEEPINTVL
                        try { android.system.Os.setsockoptInt(fd, android.system.OsConstants.IPPROTO_TCP, 6, 3) } catch(e: Exception) {}  // TCP_KEEPCNT
                        // TCP_FASTOPEN (server)
                        try { android.system.Os.setsockoptInt(fd, android.system.OsConstants.IPPROTO_TCP, 23, 5) } catch(e: Exception) {}
                        // TCP_FASTOPEN_CONNECT (client)
                        try { android.system.Os.setsockoptInt(fd, android.system.OsConstants.IPPROTO_TCP, 30, 1) } catch(e: Exception) {}
                        // TCP_QUICKACK
                        try { android.system.Os.setsockoptInt(fd, android.system.OsConstants.IPPROTO_TCP, 12, 1) } catch(e: Exception) {}
                        // TCP_CONGESTION (BBR if available, else CUBIC)
                        try {
                            val osClass = Class.forName("android.system.Os")
                            val method = osClass.getMethod("setsockoptString", java.io.FileDescriptor::class.java, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType, String::class.java)
                            method.invoke(null, fd, android.system.OsConstants.IPPROTO_TCP, 13, "bbr")
                        } catch (e: Exception) {
                            try {
                                val osClass = Class.forName("android.system.Os")
                                val method = osClass.getMethod("setsockoptString", java.io.FileDescriptor::class.java, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType, String::class.java)
                                method.invoke(null, fd, android.system.OsConstants.IPPROTO_TCP, 13, "cubic")
                            } catch (ex: Exception) {}
                        }
                    }
                    // IP_TOS (Low Delay / High Throughput)
                    try { android.system.Os.setsockoptInt(fd, android.system.OsConstants.IPPROTO_IP, android.system.OsConstants.IP_TOS, 0x10) } catch(e: Exception) {}
                } catch (e: Exception) {
                } finally {
                    try { pfd?.close() } catch (e: Exception) {}
                }
            }
        } catch (e: Exception) {}
    }
}
