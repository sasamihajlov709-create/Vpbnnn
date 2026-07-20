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

    private val _rttJitter = MutableStateFlow(0L)
    val rttJitter: StateFlow<Long> = _rttJitter.asStateFlow()

    private val rttHistory = mutableListOf<Long>()

    val currentJitterFactor: Double
        get() = (_rttJitter.value.toDouble() / 100.0).coerceAtMost(2.0).coerceAtLeast(0.0)

    private val _fragmentationErrors = MutableStateFlow(0)
    val fragmentationErrors: StateFlow<Int> = _fragmentationErrors.asStateFlow()

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
    
    private val lastDataSent = AtomicLong(System.currentTimeMillis())
    private val lastDataReceived = AtomicLong(System.currentTimeMillis())

    fun recordDataSent() { lastDataSent.set(System.currentTimeMillis()) }
    fun recordDataReceived() { lastDataReceived.set(System.currentTimeMillis()) }

    private val slidingWindow = java.util.Collections.synchronizedList(mutableListOf<Boolean>())
    private val WINDOW_SIZE = 100

    private val censorshipWindow = java.util.Collections.synchronizedList(mutableListOf<Boolean>())
    private val CENSOR_WINDOW_SIZE = 40

    private val lastBytes = AtomicLong(0L)
    private val lastTime = AtomicLong(System.currentTimeMillis())
    
    @Volatile var isMonitoring = false

    init {
        kotlinx.coroutines.CoroutineScope(Dispatchers.Default).launch {
            while (true) {
                if (isMonitoring) {
                    updateSpeed()
                }
                delay(1000)
            }
        }

        kotlinx.coroutines.CoroutineScope(Dispatchers.Default).launch {
            while (true) {
                if (isMonitoring) {
                    delay(5000)
                    _topHosts.value = hostCounter.entries
                    .sortedByDescending { it.value.get() }
                    .take(10)
                    .map { it.key to it.value.get() }
                
                // Prune hostCounter if too large
                if (hostCounter.size > 500) {
                    val toKeep = hostCounter.entries
                        .sortedByDescending { it.value.get() }
                        .take(200)
                        .map { it.key }
                        .toSet()
                    hostCounter.keys.retainAll(toKeep)
                }
                if (hostCounter.size > 2000) {
                    val keysToRemove = hostCounter.entries
                        .sortedBy { it.value.get() }
                        .take(500)
                        .map { it.key }
                    keysToRemove.forEach { hostCounter.remove(it) }
                }
                
                updateSuccessRate()

                val nowTime = System.currentTimeMillis()
                // Long polling and idle connections are common. Only trigger stall watchdog
                // if there are many active connections but no traffic for a longer period (e.g. 2 minutes),
                // and we are experiencing connection issues.
                if (nowTime - lastDataSent.get() > 120000 && nowTime - lastDataReceived.get() > 120000 && _activeConnections.value > 5 && _successRate.value < 80) { 
                     logRecovery("WATCHDOG: Stall detected. Force re-adaptation.")
                     forceReAdaptation()
                     lastDataSent.set(nowTime)
                     lastDataReceived.set(nowTime)
                }
                } else {
                    delay(5000)
                }
            }
        }
        
        kotlinx.coroutines.CoroutineScope(Dispatchers.IO).launch {
            delay(30000)
            while (true) {
                if (isMonitoring && _activeConnections.value < 2 && _topHosts.value.isNotEmpty()) {
                    val target = _topHosts.value.random().first
                    BypassConfig.shadowProbe(target)
                }
                delay(60000 + (0..60000).random().toLong())
            }
        }

        kotlinx.coroutines.CoroutineScope(Dispatchers.IO).launch {
            val canaries = listOf("google.com", "wikipedia.org", "openai.com", "facebook.com", "github.com")
            delay(15000)
            while (true) {
                if (isMonitoring) {
                    var failures = 0
                    for (canary in canaries) {
                        try {
                            withTimeout(5000) {
                                BypassConfig.shadowProbe(canary)
                            }
                        } catch (e: Exception) {
                            failures++
                        }
                        delay(2000)
                    }
                    
                    if (failures >= 3) {
                        val current = _censorshipIntensity.value
                        _censorshipIntensity.value = (current + 20).coerceAtMost(100)
                        logRecovery("CORE: Canary failed ($failures/5). Censorship Suspected: ${_censorshipIntensity.value}%")
                        if (_censorshipIntensity.value > 90) forceReAdaptation()
                    } else if (failures == 0) {
                        _censorshipIntensity.value = (_censorshipIntensity.value - 5).coerceAtLeast(0)
                    }
                }
                delay(300000)
            }
        }
    }

    fun forceReAdaptation() {
        logRecovery("CORE: Executing Full Kernel Re-Adaptation.")
        BypassConfig.resetCaches()
        consecutiveErrors.set(0)
        synchronized(slidingWindow) { slidingWindow.clear() }
        synchronized(censorshipWindow) { censorshipWindow.clear() }
        updateSuccessRate()
    }

    private val _proxyHealthTrigger = kotlinx.coroutines.flow.MutableSharedFlow<String>(extraBufferCapacity = 1)
    val proxyHealthTrigger = _proxyHealthTrigger.asSharedFlow()

    fun recordFragmentationError() {
        _fragmentationErrors.update { it + 1 }
    }

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
        
        if (totalRequests.get() > 50) {
            val rate = getSuccessRate()
            if (rate < 10) {
                BypassConfig.resetToDefaults()
                totalRequests.set(0)
                totalErrors.set(0)
                synchronized(slidingWindow) { slidingWindow.clear() }
                updateSuccessRate()
            }
        }
    }

    fun addRequest() {
        totalRequests.incrementAndGet()
    }

    fun recordGlobalSuccess(rtt: Long = -1) {
        if (rtt > 0) {
            synchronized(rttHistory) {
                rttHistory.add(rtt)
                if (rttHistory.size > 20) rttHistory.removeAt(0)
                if (rttHistory.size >= 2) {
                    var totalDiff = 0L
                    for (i in 1 until rttHistory.size) {
                        totalDiff += Math.abs(rttHistory[i] - rttHistory[i-1])
                    }
                    _rttJitter.value = totalDiff / (rttHistory.size - 1)
                }
            }
        }
        consecutiveErrors.set(0)
        addToWindow(true)
    }

    private fun addToWindow(success: Boolean) {
        synchronized(slidingWindow) {
            slidingWindow.add(success)
            if (slidingWindow.size > WINDOW_SIZE) slidingWindow.removeAt(0)
        }
        
        synchronized(censorshipWindow) {
            censorshipWindow.add(success)
            if (censorshipWindow.size > CENSOR_WINDOW_SIZE) censorshipWindow.removeAt(0)
            
            val failureCount = censorshipWindow.count { !it }
            val newIntensity = (failureCount.toDouble() / CENSOR_WINDOW_SIZE * 100).toInt()
            if (newIntensity != _censorshipIntensity.value) {
                _censorshipIntensity.value = newIntensity
                if (newIntensity > 70) logRecovery("CORE: High censorship detected ($newIntensity%).")
            }
        }
        updateSuccessRate()
        
        if (slidingWindow.size >= 20) {
            val rate = getSuccessRate()
            BypassConfig.adjustMtu(rate)
            if (rate < 35) {
                val now = System.currentTimeMillis()
                if (now - lastGlobalRotation.get() > 60000) {
                    lastGlobalRotation.set(now)
                    logRecovery("CORE: Critical success rate ($rate%). Rotating core strategy.")
                    BypassConfig.rotateGlobalStrategy()
                    synchronized(slidingWindow) { slidingWindow.clear() }
                }
            }
        }
    }

    private val lastGlobalRotation = AtomicLong(0L)

    private val _signalQuality = MutableStateFlow(100)
    val signalQuality: StateFlow<Int> = _signalQuality.asStateFlow()

    private fun updateSuccessRate() {
        val rate = getSuccessRate()
        _successRate.value = rate
        
        // Calculate Signal Quality (0-100)
        val rtt = BypassConfig.currentRttMs.value
        val rttWeight = if (rtt < 100) 40 else if (rtt < 300) 25 else 10
        val successWeight = (rate * 0.6).toInt()
        _signalQuality.value = (rttWeight + successWeight).coerceIn(0, 100)
        
        // Auto-Panic Logic
        if (slidingWindow.size >= 30) {
            if (rate < 20 && !BypassConfig.isPanicMode) {
                BypassConfig.panicOptimize()
            } else if (rate > 80 && BypassConfig.isPanicMode) {
                BypassConfig.exitPanicMode()
            }
        }
        
        performAutoTuning()
    }

    private var lastTuningTime = 0L
    private fun performAutoTuning() {
        if (!BypassConfig.isAutoTuning) return
        val now = System.currentTimeMillis()
        if (now - lastTuningTime < 60000) return
        lastTuningTime = now
        val rate = _successRate.value
        if (slidingWindow.size < 25) return

        if (rate < 60) {
            if (BypassConfig.frag1 > 1) BypassConfig.frag1--
            if (BypassConfig.delay1 < 100) BypassConfig.delay1 += 10
        } else if (rate > 95) {
            if (BypassConfig.frag1 < 8) BypassConfig.frag1++
            if (BypassConfig.delay1 > 15) BypassConfig.delay1 -= 5
        }
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

    fun addConnection() = _activeConnections.update { it + 1 }
    fun removeConnection() = _activeConnections.update { if (it > 0) it - 1 else 0 }
    fun forceRecovery(reason: String) = _proxyHealthTrigger.tryEmit(reason)

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

    fun recordCensorshipEvent(interfered: Boolean) {
        addToWindow(!interfered)
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
        synchronized(censorshipWindow) { censorshipWindow.clear() }
        if (clearLog) _recoveryLog.value = emptyList()
        _topHosts.value = emptyList()
        hostCounter.clear()
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
            
            // Periodically update top hosts
            if (bytesDiff > 0 && currentTime % 5000 < 1000) {
                _topHosts.value = hostCounter.entries
                    .sortedByDescending { it.value.get() }
                    .take(10)
                    .map { it.key to it.value.get() }
            }
        }
    }

    fun formatBytes(bytes: Long): String {
        if (bytes < 1024) return "$bytes B"
        if (bytes < 1024 * 1024) return String.format(java.util.Locale.US, "%.1f KB", bytes / 1024.0)
        if (bytes < 1024 * 1024 * 1024) return String.format(java.util.Locale.US, "%.1f MB", bytes / (1024.0 * 1024.0))
        return String.format(java.util.Locale.US, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0))
    }

    fun recordSuccess(strategy: BypassStrategy, rtt: Long = -1L, context: android.content.Context? = null) {
        recordGlobalSuccess(rtt)
        BypassConfig.recordSuccess(strategy, rtt, context)
    }

    fun recordFailure(strategy: BypassStrategy, isCritical: Boolean = false, context: android.content.Context? = null) {
        BypassConfig.recordFailure(strategy, isCritical, context)
    }

    fun autoCleanup() {}
}

enum class BypassStrategy {
    FAKE_PACKET, SNI_SPLIT, SNI_TRIPLE, SNI_MANGLE, TLS_DIRTY, TLS_PAD, TLS_GREASE,
    HOST_MIXED, FRAG_3_5, CHUNKY, HOST_CASE, RAND_SPLIT, HEADER_SPLIT,
    TCP_OOB_DESYNC, HTTP_SPACE, HTTP_TAB, WINDOW_SIZE, SLOW_SEND, OOB_DESYNC,
    TCP_ZERO_WINDOW, GHOST_PACKETS, FRAGMENT_MULTI, HTTP_MANGLE, DIRECT
}

enum class NetworkType { WIFI, MOBILE, UNKNOWN }
enum class HostCategory { STREAMING, SOCIAL, MESSENGER, SEARCH, AI, FINANCE, CDN, NEWS, GAMING, SHOPPING, DEV, OTHER }

object HostClassifier {
    fun classify(host: String): HostCategory {
        val lower = host.lowercase(java.util.Locale.ROOT)
        return when {
            lower.contains("youtube") || lower.contains("googlevideo") || lower.contains("ytimg") ||
            lower.contains("ggpht") || lower.contains("twitch") || lower.contains("netflix") ||
            lower.contains("tiktok") || lower.contains("video.") || lower.contains("stream") -> HostCategory.STREAMING
            lower.contains("instagram") || lower.contains("facebook") || lower.contains("fbcdn") ||
            lower.contains("twitter") || lower.contains("x.com") || lower.contains("reddit") ||
            lower.contains("vk.com") || lower.contains("linkedin") -> HostCategory.SOCIAL
            lower.contains("telegram") || lower.contains("t.me") || lower.contains("whatsapp") ||
            lower.contains("signal") || lower.contains("discord") || lower.contains("slack") -> HostCategory.MESSENGER
            lower.contains("google.") || lower.contains("bing") || lower.contains("duckduckgo") ||
            lower.contains("yandex") || lower.contains("baidu") -> HostCategory.SEARCH
            lower.contains("openai") || lower.contains("chatgpt") || lower.contains("anthropic") ||
            lower.contains("claude") || lower.contains("deepmind") || lower.contains("gemini") -> HostCategory.AI
            else -> HostCategory.OTHER
        }
    }
}

object BypassConfig {
    @Volatile var activeVpnService: android.net.VpnService? = null
    var frag1 = 3
    var frag2 = 5
    var frag3 = 2
    var delay1 = 25L
    var delay2 = 20L
    var fakeTtl = 3
    var blockQuic = true
    var isAutoTuning = true
    var isPanicMode = false

    private val _currentStrategy = MutableStateFlow(BypassStrategy.FAKE_PACKET)
    val strategy: StateFlow<BypassStrategy> = _currentStrategy.asStateFlow()

    private val _currentRttMs = MutableStateFlow(100L)
    val currentRttMs: StateFlow<Long> = _currentRttMs.asStateFlow()

    val currentMtu = MutableStateFlow(1400)

    data class HostDna(
        var frag1: Int,
        var frag2: Int,
        var delay1: Long,
        var strategy: BypassStrategy? = null,
        var lastSuccess: Long = System.currentTimeMillis()
    )

    private val hostDnas = ConcurrentHashMap<String, HostDna>()
    private val hostFailedStrategies = ConcurrentHashMap<String, MutableSet<BypassStrategy>>()
    private val hostSuccessStrategies = ConcurrentHashMap<String, BypassStrategy>()
    private val hostSuccessCount = ConcurrentHashMap<String, Int>()
    private val hostStrategyCache = ConcurrentHashMap<String, Pair<BypassStrategy, Int>>()
    private val hostTtlMap = ConcurrentHashMap<String, Int>()
    private val hostExplorationTtl = ConcurrentHashMap<String, Int>()
    private val hostConsecutiveFailures = ConcurrentHashMap<String, Int>()
    private val hostConsecutiveSuccesses = ConcurrentHashMap<String, Int>()
    private val lastFailureTime = ConcurrentHashMap<String, Long>()
    private val directPathHosts = java.util.Collections.synchronizedSet(mutableSetOf<String>())
    private val dynamicallyCensoredHosts = ConcurrentHashMap<String, Long>()
    private val strategyScores = ConcurrentHashMap<String, ConcurrentHashMap<BypassStrategy, Int>>()

    fun recordStrategyResult(host: String, strategy: BypassStrategy, success: Boolean) {
        val scores = strategyScores.getOrPut(host) { ConcurrentHashMap() }
        val current = scores.getOrDefault(strategy, 50)
        if (success) {
            scores[strategy] = (current + 5).coerceAtMost(100)
        } else {
            scores[strategy] = (current - 15).coerceAtLeast(0)
        }
    }

    private val _currentFragSize = AtomicInteger(1)
    private val _currentFragSizeState = MutableStateFlow(1)
    val currentFragSizeState: StateFlow<Int> = _currentFragSizeState.asStateFlow()

    private val wifiStrategyScores = ConcurrentHashMap<BypassStrategy, Int>()
    private val mobileStrategyScores = ConcurrentHashMap<BypassStrategy, Int>()
    private val wifiCategoryScores = ConcurrentHashMap<HostCategory, ConcurrentHashMap<BypassStrategy, Int>>()
    private val mobileCategoryScores = ConcurrentHashMap<HostCategory, ConcurrentHashMap<BypassStrategy, Int>>()

    private val defaultScores = mapOf(
        BypassStrategy.FAKE_PACKET to 500, BypassStrategy.TCP_OOB_DESYNC to 400,
        BypassStrategy.SNI_TRIPLE to 350, BypassStrategy.SNI_SPLIT to 300,
        BypassStrategy.TLS_PAD to 250, BypassStrategy.TLS_GREASE to 250,
        BypassStrategy.FRAGMENT_MULTI to 450, BypassStrategy.GHOST_PACKETS to 200, BypassStrategy.DIRECT to 1
    )

    private val globalStrategyScores = ConcurrentHashMap<BypassStrategy, Int>().apply { putAll(defaultScores) }

    fun getDnaForHost(host: String): HostDna = hostDnas.getOrPut(host) { HostDna(frag1, frag2, delay1) }

    fun mutateDnaForHost(host: String) {
        val dna = getDnaForHost(host)
        dna.frag1 = (1..10).random()
        dna.frag2 = (2..15).random()
        dna.delay1 = (10..150).random().toLong()
        dna.strategy = null 
    }

    fun getAdaptiveDelay1(): Long {
        val baseDelay = (_currentRttMs.value / 4).coerceIn(10L, 100L) + (0..ProxyStats.rttJitter.value.coerceAtMost(50).toInt()).random()
        val hour = java.util.Calendar.getInstance().get(java.util.Calendar.HOUR_OF_DAY)
        return if (hour in 19..23) (baseDelay * 1.5).toLong() else baseDelay
    }

    fun getCurrentFragSize(): Int {
        val base = _currentFragSize.get().coerceIn(1, 15)
        val hour = java.util.Calendar.getInstance().get(java.util.Calendar.HOUR_OF_DAY)
        return if (hour in 19..23) (base * 0.7).toInt().coerceAtLeast(1) else base
    }

    fun getAdaptiveDelay2(): Long = (_currentRttMs.value / 8).coerceIn(5L, 50L) + (0..ProxyStats.rttJitter.value.coerceAtMost(20).toInt()).random()

    fun resetCaches() {
        hostDnas.clear(); hostFailedStrategies.clear(); hostStrategyCache.clear(); hostSuccessStrategies.clear()
        hostSuccessCount.clear(); hostExplorationTtl.clear(); hostTtlMap.clear(); hostConsecutiveFailures.clear()
        hostConsecutiveSuccesses.clear(); directPathHosts.clear(); dynamicallyCensoredHosts.clear(); RobustResolver.clearCache()
    }

    fun resetToDefaults() {
        resetCaches(); strategyScores.clear(); globalStrategyScores.clear(); globalStrategyScores.putAll(defaultScores)
        wifiStrategyScores.clear(); wifiStrategyScores.putAll(defaultScores)
        mobileStrategyScores.clear(); mobileStrategyScores.putAll(defaultScores)
        frag1 = 3; frag2 = 5; delay1 = 25L; currentMtu.value = 1400; _currentFragSize.set(1); _currentFragSizeState.value = 1
    }

    private val baseBlockedHosts = setOf("youtube", "googlevideo", "ytimg", "ggpht", "google", "telegram", "t.me", "instagram", "facebook", "twitter", "x.com", "discord", "chatgpt", "openai")
    private var lastPruneTime = 0L

    fun isHostCensored(host: String): Boolean {
        val lower = host.lowercase(java.util.Locale.ROOT)
        if (baseBlockedHosts.any { lower.contains(it) }) return true
        
        val now = System.currentTimeMillis()
        // Prune periodically instead of every call
        if (now - lastPruneTime > 3600000) { // Every hour
            lastPruneTime = now
            val it = dynamicallyCensoredHosts.entries.iterator()
            while (it.hasNext()) {
                if (now - it.next().value > 86400000) it.remove()
            }
        }

        return dynamicallyCensoredHosts.keys.any { lower.contains(it) }
    }

    fun markHostAsCensored(host: String) {
        if (host.length > 3 && !isHostCensored(host)) {
            dynamicallyCensoredHosts[host] = System.currentTimeMillis()
            ProxyStats.logRecovery("CORE: Identified $host as CENSORED.")
        }
    }

    private fun getNetworkScoresMap(): ConcurrentHashMap<BypassStrategy, Int> {
        val map = if (_currentNetworkType.value == NetworkType.MOBILE) mobileStrategyScores else wifiStrategyScores
        if (map.isEmpty()) {
            map.putAll(defaultScores)
        }
        return map
    }

    fun recordSuccessForHost(host: String, strategy: BypassStrategy, rtt: Long = -1, context: android.content.Context? = null) {
        ProxyStats.recordCensorshipEvent(false); ProxyStats.recordGlobalSuccess(rtt)
        hostConsecutiveFailures.remove(host)
        recordStrategyResult(host, strategy, true)
        val successes = (hostConsecutiveSuccesses[host] ?: 0) + 1
        hostConsecutiveSuccesses[host] = successes
        if (strategy == BypassStrategy.DIRECT && successes >= 15) directPathHosts.add(host)

        val dna = getDnaForHost(host); dna.lastSuccess = System.currentTimeMillis(); dna.strategy = strategy
        if (Math.random() > 0.8 && dna.frag1 < 10) { dna.frag1++; if (dna.delay1 > 10) dna.delay1 -= 1 }

        hostSuccessStrategies[host] = strategy
        hostSuccessCount[host] = (hostSuccessCount[host] ?: 0) + 1
        hostFailedStrategies.remove(host)
        if (strategy == BypassStrategy.FAKE_PACKET) hostTtlMap[host] = hostExplorationTtl[host] ?: 3
        
        getNetworkScoresMap()[strategy] = (getNetworkScoresMap()[strategy] ?: 100) + 5
        if (context != null) saveScores(context)
    }

    fun recordFailureForHost(host: String, strategy: BypassStrategy, isCritical: Boolean = false, context: android.content.Context? = null) {
        ProxyStats.recordCensorshipEvent(true)
        hostConsecutiveSuccesses.remove(host); directPathHosts.remove(host)
        recordStrategyResult(host, strategy, false)
        val networkScores = getNetworkScoresMap()
        val penalty = if (isCritical) 20 else 10
        networkScores[strategy] = ((networkScores[strategy] ?: 100) - penalty).coerceAtLeast(10)
        
        hostFailedStrategies.getOrPut(host) { java.util.Collections.synchronizedSet(mutableSetOf()) }.add(strategy)
        lastFailureTime[host] = System.currentTimeMillis()

        if (strategy == BypassStrategy.FAKE_PACKET) {
            val exp = hostExplorationTtl[host] ?: 3
            hostExplorationTtl[host] = if (exp < 12) exp + 1 else 3
        }

        val failures = (hostConsecutiveFailures[host] ?: 0) + 1
        hostConsecutiveFailures[host] = failures
        if (failures >= 2) { markHostAsCensored(host); mutateDnaForHost(host) }
        if (failures >= 3 && context != null) RobustResolver.clearCacheForHost(host)

        if (isCritical) { hostStrategyCache.remove(host); RobustResolver.clearCacheForHost(host) }
        if (context != null) saveScores(context)
    }

    suspend fun shadowProbe(host: String, specificStrategy: BypassStrategy? = null) {
        val strategiesToTest = if (specificStrategy != null) listOf(specificStrategy) 
            else listOf(BypassStrategy.TCP_OOB_DESYNC, BypassStrategy.SNI_TRIPLE, BypassStrategy.TLS_DIRTY)
            
        val service = activeVpnService ?: return
        if (service is PinkVpnService) {
            for (strategy in strategiesToTest) {
                service.getServiceScope().launch {
                    try {
                        val ips = RobustResolver.resolve(host, null); if (ips.isEmpty()) return@launch
                        val startTime = System.currentTimeMillis(); val socket = Socket()
                        service.protect(socket)
                        try {
                            withTimeout(4000) {
                                socket.connect(InetSocketAddress(ips.first(), 443), 2500)
                                val hello = FakePacketHelper.buildFakeClientHello(host, (40..90).random())
                                applyBypass(socket, socket.getOutputStream(), hello, hello.size, getSessionConfig(host, strategy, 100L), host)
                                socket.getOutputStream().flush()
                                val response = ByteArray(5)
                                if (socket.getInputStream().read(response) >= 1) {
                                    recordStrategyResult(host, strategy, true)
                                    recordSuccessForHost(host, strategy, System.currentTimeMillis() - startTime)
                                }
                            }
                        } finally {
                            try { socket.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                        }
                    } catch (e: Exception) { 
                        recordStrategyResult(host, strategy, false)
                    }
                }
            }
        }
    }

    fun resolveStrategyForHost(host: String): BypassStrategy {
        if (directPathHosts.contains(host)) return BypassStrategy.DIRECT
        
        // Intelligent selection based on past performance
        val dna = getDnaForHost(host)
        val cachedStrategy = dna.strategy; if (cachedStrategy != null && (hostSuccessCount[host] ?: 0) > 10) return cachedStrategy
        
        val scores = strategyScores.getOrPut(host) { ConcurrentHashMap() }
        val bestInScore = scores.entries.filter { it.value > 70 }.maxByOrNull { it.value }?.key
        if (bestInScore != null) return bestInScore

        hostStrategyCache[host]?.let { if (it.second > 3) return it.first }
        val failed = hostFailedStrategies[host] ?: emptySet<BypassStrategy>()
        
        // Prefer strategies that are known to work in high censorship
        val pool = if (ProxyStats.censorshipIntensity.value > 80) {
            listOf(BypassStrategy.FAKE_PACKET, BypassStrategy.TCP_OOB_DESYNC, BypassStrategy.SNI_MANGLE)
        } else {
            BypassStrategy.entries.filter { it != BypassStrategy.DIRECT && it !in failed }
        }
        
        val candidates = pool.filter { it !in failed }
        if (candidates.isEmpty()) return _currentStrategy.value
        return candidates.random()
    }

    fun reOptimize() {
        // Placeholder for future global optimization triggers
        ProxyStats.logRecovery("CORE: Global re-optimization triggered.")
    }

    fun runGlobalOptimization() {
        if (!isAutoTuning) return
        
        ProxyStats.logRecovery("CORE: Running global optimization...")
        
        // Find strategy with highest global success rate across all hosts
        val allEntries = strategyScores.values.flatMap { it.entries }
        val bestGlobal = allEntries.groupBy { it.key }
            .mapValues { group -> group.value.map { it.value }.average() }
            .maxByOrNull { it.value }
            
        if (bestGlobal != null && bestGlobal.value > 75) {
            if (_currentStrategy.value != bestGlobal.key) {
                _currentStrategy.value = bestGlobal.key
                ProxyStats.logRecovery("CORE: Auto-tuned global strategy to ${bestGlobal.key}")
            }
        }
        
        // Cleanup old DNS/Host data to prevent memory leaks
        val now = System.currentTimeMillis()
        if (strategyScores.size > 500) {
            val it = strategyScores.entries.iterator()
            var count = 0
            while (it.hasNext() && count < 100) {
                it.next()
                it.remove()
                count++
            }
        }
        
        // Prune other host-specific maps
        listOf(hostDnas, hostFailedStrategies, hostSuccessStrategies, hostSuccessCount, 
               hostStrategyCache, hostTtlMap, hostExplorationTtl, hostConsecutiveFailures, 
               hostConsecutiveSuccesses, lastFailureTime, dynamicallyCensoredHosts).forEach { map ->
            if (map.size > 1000) {
                val it = map.entries.iterator()
                var count = 0
                while (it.hasNext() && count < 200) {
                    it.next()
                    it.remove()
                    count++
                }
            }
        }
    }

    suspend fun applyBypass(socket: Socket, out: OutputStream, data: ByteArray, len: Int, config: SessionConfig, host: String) {
        if (len <= 0) return
        if (len == 1) {
            out.write(data, 0, len)
            out.flush()
            return
        }
        when (config.strategy) {
            BypassStrategy.FAKE_PACKET -> {
                val fake = FakePacketHelper.buildFakeClientHello(host, (40..120).random())
                out.write(fake); out.flush(); delay(config.delay1); out.write(data, 0, len)
            }
            BypassStrategy.SNI_SPLIT -> {
                val split = config.frag1.coerceIn(1, len - 1)
                out.write(data, 0, split); out.flush(); delay(config.delay1); out.write(data, split, len - split)
            }
            BypassStrategy.SNI_TRIPLE -> {
                val split1 = (len / 3).coerceAtLeast(1)
                val split2 = (2 * len / 3).coerceAtLeast(split1 + 1).coerceAtMost(len - 1)
                out.write(data, 0, split1); out.flush(); delay(config.delay1)
                out.write(data, split1, split2 - split1); out.flush(); delay(config.delay2)
                out.write(data, split2, len - split2)
            }
            BypassStrategy.TCP_OOB_DESYNC -> {
                try {
                    socket.sendUrgentData(0xFF)
                } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                out.write(data, 0, len)
            }
            BypassStrategy.GHOST_PACKETS -> {
                val ghost = ByteArray((20..50).random()) { (0..255).random().toByte() }
                out.write(ghost); out.flush(); delay(10)
                out.write(data, 0, len)
            }
            BypassStrategy.FRAGMENT_MULTI -> {
                val chunkSize = (len / 5).coerceAtLeast(1)
                var offset = 0
                while (offset < len) {
                    val currentRead = (len - offset).coerceAtMost(chunkSize)
                    out.write(data, offset, currentRead); out.flush()
                    offset += currentRead
                    delay(5)
                }
            }
            BypassStrategy.TLS_DIRTY -> {
                val dirty = ByteArray((10..30).random()) { (0..255).random().toByte() }
                out.write(dirty); out.flush(); delay(15)
                out.write(data, 0, len)
            }
            BypassStrategy.HTTP_MANGLE -> {
                val mangled = if (len > 10 && data[0] == 'G'.code.toByte() && data[1] == 'E'.code.toByte()) {
                    val str = String(data, 0, len)
                    str.replace("GET ", "gEt ").replace("Host: ", "hOsT: ").toByteArray()
                } else data
                out.write(mangled, 0, if (mangled === data) len else mangled.size)
            }
            BypassStrategy.SNI_MANGLE -> {
                val fakeHello = FakePacketHelper.buildFakeClientHello("google.com", (50..100).random())
                out.write(fakeHello); out.flush(); delay(20)
                out.write(data, 0, len)
            }
            BypassStrategy.TLS_PAD -> {
                val split = (len / 2).coerceAtLeast(1)
                out.write(data, 0, split)
                val padding = ByteArray((32..128).random()) { 0 }
                out.write(padding); out.flush(); delay(15)
                out.write(data, split, len - split)
            }
            BypassStrategy.TLS_GREASE -> {
                val grease = byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x04, 0x0A, 0x0A, 0x0A, 0x0A)
                out.write(grease); out.flush(); delay(10)
                out.write(data, 0, len)
            }
            BypassStrategy.HOST_MIXED -> {
                val sniOffset = TlsParser.findSniOffset(data, len, host)
                if (sniOffset >= 2 && sniOffset < len) {
                    var hostnameLen = ((data[sniOffset - 2].toInt() and 0xFF) shl 8) or (data[sniOffset - 1].toInt() and 0xFF)
                    if (hostnameLen <= 0 || hostnameLen > 256 || sniOffset + hostnameLen >= len) {
                        hostnameLen = host.length
                    }
                    if (sniOffset + hostnameLen < len) {
                        val split = sniOffset + (hostnameLen / 2)
                        out.write(data, 0, split); out.flush(); delay(config.delay1)
                        out.write(data, split, len - split)
                    } else {
                        val split = (len / 2).coerceAtLeast(1)
                        out.write(data, 0, split); out.flush(); delay(config.delay1)
                        out.write(data, split, len - split)
                    }
                } else if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val str = String(data, 0, len)
                    val mangled = str.replace("Host: ", "hOsT: ").replace("host: ", "HoSt: ")
                    val mBytes = mangled.toByteArray()
                    out.write(mBytes, 0, mBytes.size)
                } else {
                    val split = (len / 2).coerceAtLeast(1)
                    out.write(data, 0, split); out.flush(); delay(config.delay1)
                    out.write(data, split, len - split)
                }
            }
            BypassStrategy.FRAG_3_5 -> {
                if (len > 8) {
                    out.write(data, 0, 3); out.flush(); delay(config.delay1)
                    out.write(data, 3, 5); out.flush(); delay(config.delay2)
                    out.write(data, 8, len - 8)
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.CHUNKY -> {
                if (len > 25) {
                    out.write(data, 0, 1); out.flush(); delay(5)
                    out.write(data, 1, 12); out.flush(); delay(5)
                    out.write(data, 13, 7); out.flush(); delay(5)
                    out.write(data, 20, len - 20)
                } else {
                    val half = (len / 2).coerceAtLeast(1)
                    out.write(data, 0, half); out.flush(); delay(5)
                    out.write(data, half, len - half)
                }
            }
            BypassStrategy.HOST_CASE -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte() || data[0] == 'H'.code.toByte())) {
                    val str = String(data, 0, len)
                    val mangled = str
                        .replace("GET ", "gEt ")
                        .replace("POST ", "PoSt ")
                        .replace("HTTP/1.1", "hTtP/1.1")
                        .replace("Host: ", "HOST: ")
                    val mBytes = mangled.toByteArray()
                    out.write(mBytes, 0, mBytes.size)
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.RAND_SPLIT -> {
                val split = if (len > 2) (1 until len).random() else 1
                out.write(data, 0, split); out.flush(); delay(config.delay1)
                out.write(data, split, len - split)
            }
            BypassStrategy.HEADER_SPLIT -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val str = String(data, 0, len)
                    val firstNl = str.indexOf("\r\n")
                    if (firstNl != -1) {
                        val head = str.substring(0, firstNl + 2)
                        val tail = str.substring(firstNl + 2)
                        val customHeaders = "X-Padding-G: ${(1000..9999).random()}\r\nX-Resilience: Active\r\n"
                        val full = head + customHeaders + tail
                        val fBytes = full.toByteArray()
                        out.write(fBytes, 0, fBytes.size)
                    } else {
                        out.write(data, 0, len)
                    }
                } else if (len > 5 && data[0] == 0x16.toByte()) {
                    out.write(data, 0, 5); out.flush(); delay(config.delay1)
                    out.write(data, 5, len - 5)
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.HTTP_SPACE -> {
                if (len > 10 && data[0] == 'G'.code.toByte() && data[1] == 'E'.code.toByte()) {
                    val str = String(data, 0, len)
                    val mangled = str.replace("GET ", "GET  ")
                    val mBytes = mangled.toByteArray()
                    out.write(mBytes, 0, mBytes.size)
                } else {
                    val split = config.frag1.coerceIn(1, len - 1)
                    out.write(data, 0, split); out.flush(); delay(config.delay1)
                    out.write(data, split, len - split)
                }
            }
            BypassStrategy.HTTP_TAB -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val str = String(data, 0, len)
                    val mangled = str.replace("Host: ", "Host:\t")
                    val mBytes = mangled.toByteArray()
                    out.write(mBytes, 0, mBytes.size)
                } else {
                    val split = config.frag1.coerceIn(1, len - 1)
                    out.write(data, 0, split); out.flush(); delay(config.delay1)
                    out.write(data, split, len - split)
                }
            }
            BypassStrategy.WINDOW_SIZE, BypassStrategy.TCP_ZERO_WINDOW -> {
                var offset = 0
                while (offset < len) {
                    val chunkSize = if (offset == 0) 1 else (1..3).random()
                    val writeLen = (len - offset).coerceAtMost(chunkSize)
                    out.write(data, offset, writeLen); out.flush()
                    offset += writeLen
                    delay(8)
                }
            }
            BypassStrategy.SLOW_SEND -> {
                var offset = 0
                while (offset < len) {
                    val writeLen = (len - offset).coerceAtMost(2)
                    out.write(data, offset, writeLen); out.flush()
                    offset += writeLen
                    delay(12)
                }
            }
            BypassStrategy.OOB_DESYNC -> {
                try {
                    socket.sendUrgentData(0xAA)
                    delay(5)
                    socket.sendUrgentData(0xBB)
                } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                out.write(data, 0, len)
            }
            else -> { out.write(data, 0, len) }
        }
        out.flush()
    }

    fun panicOptimize() {
        isPanicMode = true
        frag1 = 1
        frag2 = 2
        delay1 = 150L
        blockQuic = true
        ProxyStats.logRecovery("CORE: ENTERING PANIC MODE (Extreme settings)")
    }

    fun exitPanicMode() {
        if (isPanicMode) {
            isPanicMode = false
            resetToDefaults()
            ProxyStats.logRecovery("CORE: EXITING PANIC MODE (Normal operation restored)")
        }
    }

    fun adjustMtu(successRate: Int) {
        val current = currentMtu.value
        if (successRate < 30 && current > 1200) {
            currentMtu.value = (current - 40).coerceAtLeast(1200)
            ProxyStats.logRecovery("CORE: MTU reduced to ${currentMtu.value} (Signal quality low)")
        } else if (successRate > 90 && current < 1500) {
            currentMtu.value = (current + 10).coerceAtMost(1500)
        }
    }

    fun setStrategy(strat: BypassStrategy) {
        _currentStrategy.value = strat
    }

    fun updateRtt(rtt: Long) {
        _currentRttMs.value = rtt
    }

    private val _currentNetworkType = MutableStateFlow(NetworkType.UNKNOWN)
    val currentNetworkType: StateFlow<NetworkType> = _currentNetworkType.asStateFlow()

    fun switchNetworkProfile(context: android.content.Context, netType: NetworkType) {
        _currentNetworkType.value = netType
    }

    fun resolveSessionConfigForHost(host: String): SessionConfig {
        val strat = resolveStrategyForHost(host)
        return getSessionConfig(host, strat, _currentRttMs.value)
    }

    fun saveTuningSettings(context: android.content.Context) {
        val prefs = context.getSharedPreferences("pink_proxy_tuning", android.content.Context.MODE_PRIVATE)
        prefs.edit().apply {
            putInt("frag1", frag1)
            putInt("frag2", frag2)
            putInt("frag3", frag3)
            putLong("delay1", delay1)
            putLong("delay2", delay2)
            putInt("fakeTtl", fakeTtl)
            putBoolean("blockQuic", blockQuic)
            putBoolean("isAutoTuning", isAutoTuning)
            apply()
        }
    }

    fun loadTuningSettings(context: android.content.Context) {
        val prefs = context.getSharedPreferences("pink_proxy_tuning", android.content.Context.MODE_PRIVATE)
        frag1 = prefs.getInt("frag1", frag1)
        frag2 = prefs.getInt("frag2", frag2)
        frag3 = prefs.getInt("frag3", frag3)
        delay1 = prefs.getLong("delay1", delay1)
        delay2 = prefs.getLong("delay2", delay2)
        fakeTtl = prefs.getInt("fakeTtl", fakeTtl)
        blockQuic = prefs.getBoolean("blockQuic", blockQuic)
        isAutoTuning = prefs.getBoolean("isAutoTuning", isAutoTuning)
    }
    
    fun clearScores(context: android.content.Context? = null) {
        resetToDefaults()
        if (context != null) {
            val prefs = context.getSharedPreferences("pink_proxy_scores", android.content.Context.MODE_PRIVATE)
            prefs.edit().clear().apply()
        }
    }

    fun getStrategyScore(strategy: BypassStrategy): Int {
        val scores = getNetworkScoresMap()
        return scores[strategy] ?: 100
    }
    fun rotateGlobalStrategy() { _currentStrategy.value = BypassStrategy.entries.filter { it != BypassStrategy.DIRECT && it != _currentStrategy.value }.random() }
    
    fun saveScores(context: android.content.Context) {
        // Periodic pruning of host success maps to prevent memory bloat
        if (hostSuccessStrategies.size > 1000) {
            val keys = hostSuccessStrategies.keys.toList().take(500)
            keys.forEach { hostSuccessStrategies.remove(it) }
        }
        if (hostSuccessCount.size > 1000) {
            val keys = hostSuccessCount.keys.toList().take(500)
            keys.forEach { hostSuccessCount.remove(it) }
        }

        val prefs = context.getSharedPreferences("pink_proxy_scores", android.content.Context.MODE_PRIVATE)
        val edit = prefs.edit()
        
        edit.putString("current_strategy", _currentStrategy.value.name)
        
        val censoredStr = dynamicallyCensoredHosts.entries
            .sortedByDescending { it.value }
            .take(500)
            .joinToString(";") { "${it.key}|${it.value}" }
        edit.putString("censored_hosts", censoredStr)
        
        val successStr = hostSuccessStrategies.entries
            .take(300)
            .joinToString(";") { "${it.key}|${it.value.name}" }
        edit.putString("success_strategies", successStr)
        
        val countStr = hostSuccessCount.entries
            .take(300)
            .joinToString(";") { "${it.key}|${it.value}" }
        edit.putString("success_counts", countStr)

        wifiStrategyScores.forEach { (strat, score) -> edit.putInt("wifi_${strat.name}", score) }
        mobileStrategyScores.forEach { (strat, score) -> edit.putInt("mobile_${strat.name}", score) }
        
        edit.apply()
    }
    
    fun initialize(context: android.content.Context) {
        if (context is android.net.VpnService) {
            activeVpnService = context
        }
        val prefs = context.getSharedPreferences("pink_proxy_scores", android.content.Context.MODE_PRIVATE)
        
        val stratStr = prefs.getString("current_strategy", null)
        if (stratStr != null) {
            try { _currentStrategy.value = BypassStrategy.valueOf(stratStr) } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        }
        
        val censoredStr = prefs.getString("censored_hosts", "") ?: ""
        if (censoredStr.isNotEmpty()) {
            censoredStr.split(";").forEach {
                val parts = it.split("|")
                if (parts.size == 2) {
                    val time = parts[1].toLongOrNull() ?: System.currentTimeMillis()
                    dynamicallyCensoredHosts[parts[0]] = time
                }
            }
        }
        
        val successStr = prefs.getString("success_strategies", "") ?: ""
        if (successStr.isNotEmpty()) {
            successStr.split(";").forEach {
                val parts = it.split("|")
                if (parts.size == 2) {
                    try {
                        val strat = BypassStrategy.valueOf(parts[1])
                        hostSuccessStrategies[parts[0]] = strat
                        val dna = getDnaForHost(parts[0])
                        dna.strategy = strat
                    } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                }
            }
        }
        
        val countStr = prefs.getString("success_counts", "") ?: ""
        if (countStr.isNotEmpty()) {
            countStr.split(";").forEach {
                val parts = it.split("|")
                if (parts.size == 2) {
                    val cnt = parts[1].toIntOrNull() ?: 0
                    hostSuccessCount[parts[0]] = cnt
                }
            }
        }

        BypassStrategy.entries.forEach { strat ->
            val wifiScore = prefs.getInt("wifi_${strat.name}", -1)
            if (wifiScore != -1) wifiStrategyScores[strat] = wifiScore
            
            val mobileScore = prefs.getInt("mobile_${strat.name}", -1)
            if (mobileScore != -1) mobileStrategyScores[strat] = mobileScore
        }
        Log.i("BypassConfig", "Persistent bypass configuration initialized from disk")
    }

    fun recordSuccess(strategy: BypassStrategy, rtt: Long = -1L, context: android.content.Context? = null) {
        ProxyStats.recordGlobalSuccess(rtt)
        if (context != null) saveScores(context)
    }

    fun recordFailure(strategy: BypassStrategy, isCritical: Boolean, context: android.content.Context?) {
        ProxyStats.recordCensorshipEvent(true)
        if (context != null) saveScores(context)
    }

    fun testInitialStrategies(context: android.content.Context) {
        ServiceChecker.runActiveProbing(context)
    }

    fun getSessionConfig(host: String, strategy: BypassStrategy, currentRtt: Long): SessionConfig {
        val dna = getDnaForHost(host)
        var f1 = dna.frag1; var f2 = dna.frag2; var f3 = 2; var d1 = dna.delay1; var d2 = getAdaptiveDelay2(); var ttl = 3
        if (!isAutoTuning) return SessionConfig(strategy, frag1, frag2, frag3, delay1, delay2, fakeTtl)
        
        // Intelligent TTL discovery based on RTT
        val estimatedHops = (currentRtt / 5).coerceIn(4, 15).toInt()
        
        when (strategy) {
            BypassStrategy.FAKE_PACKET -> { 
                if (isHostCensored(host)) { f1 = (f1 / 2).coerceAtLeast(1); d1 = (d1 * 1.5).toLong() }
                ttl = hostTtlMap[host] ?: estimatedHops
            }
            BypassStrategy.TCP_OOB_DESYNC -> {
                f1 = 1; d1 = (10..30).random().toLong()
            }
            BypassStrategy.GHOST_PACKETS -> {
                ttl = (2..4).random()
            }
            BypassStrategy.SNI_SPLIT, BypassStrategy.SNI_TRIPLE -> { 
                f1 = dna.frag1.coerceIn(1, 5); f2 = dna.frag2.coerceIn(2, 10); d1 = dna.delay1.coerceIn(15, 150) 
            }
            else -> { f1 = 1; d1 = dna.delay1.coerceIn(5, 50) }
        }
        return SessionConfig(strategy, f1, f2, f3, d1, d2, ttl)
    }
}

data class SessionConfig(val strategy: BypassStrategy, val frag1: Int, val frag2: Int, val frag3: Int, val delay1: Long, val delay2: Long, val fakeTtl: Int)

class PinkProxyServer(private val vpnService: android.net.VpnService, private val port: Int) {
    private val proxyDispatcher = java.util.concurrent.Executors.newCachedThreadPool().asCoroutineDispatcher()
    private var serverScope = kotlinx.coroutines.CoroutineScope(proxyDispatcher + kotlinx.coroutines.SupervisorJob())
    private var serverSocket: ServerSocket? = null
    private var udpSocket: java.net.DatagramSocket? = null
    private val bufferPool = java.util.concurrent.ConcurrentLinkedQueue<ByteArray>()
    private val BUFFER_SIZE = 16384

    private fun getBuffer(size: Int): ByteArray {
        val buf = bufferPool.poll()
        return if (buf != null && buf.size >= size) buf else ByteArray(size)
    }
    private fun releaseBuffer(buffer: ByteArray) { 
        if (buffer.size >= BUFFER_SIZE && bufferPool.size < 64) bufferPool.offer(buffer) 
    }
    private val udpSessions = ConcurrentHashMap<String, UdpSession>()
    private class UdpSession(val clientAddr: java.net.InetAddress, val clientPort: Int, val targetSocket: java.net.DatagramSocket, var lastActivity: Long = System.currentTimeMillis())


    fun start() {
        try { serverScope.cancel() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        serverScope = kotlinx.coroutines.CoroutineScope(proxyDispatcher + kotlinx.coroutines.SupervisorJob())

        serverScope.launch {
            try {
                val s = ServerSocket()
                s.reuseAddress = true
                s.bind(java.net.InetSocketAddress("127.0.0.1", port))
                serverSocket = s
                while (isActive) {
                    val clientSocket = serverSocket?.accept() ?: break
                    launch { handleClient(clientSocket) }
                }
            } catch (e: Exception) { Log.e("PinkProxyServer", "TCP Server failed", e) }
        }

        // Core Heartbeat: Proactive strategy validation
        serverScope.launch {
            while (isActive) {
                delay(45000)
                if (ProxyStats.getSuccessRate() < 50) {
                    ProxyStats.logRecovery("CORE: Low health. Probing alternatives...")
                    BypassConfig.shadowProbe("google.com")
                }
            }
        }

        // Global Optimizer: Periodically refine global settings
        serverScope.launch {
            while (isActive) {
                delay(300000) // 5 minutes
                BypassConfig.runGlobalOptimization()
            }
        }

        // UDP Proxy Start (Simple mapping for now, will expand to full SOCKS5 UDP if needed)
        serverScope.launch {
            try {
                val u = java.net.DatagramSocket(null)
                u.reuseAddress = true
                u.bind(java.net.InetSocketAddress("127.0.0.1", port + 1))
                udpSocket = u
                val buffer = ByteArray(16384)
                while (isActive) {
                    val packet = java.net.DatagramPacket(buffer, buffer.size)
                    udpSocket?.receive(packet)
                    handleUdpPacket(packet)
                }
            } catch (e: Exception) { Log.e("PinkProxyServer", "UDP Server failed", e) }
        }
        
        // UDP Session Cleanup
        serverScope.launch {
            while (isActive) {
                delay(30000)
                val now = System.currentTimeMillis()
                udpSessions.entries.removeIf { 
                    if (now - it.value.lastActivity > 60000) {
                        it.value.targetSocket.close()
                        true
                    } else false
                }
            }
        }
    }

    private suspend fun handleUdpPacket(packet: java.net.DatagramPacket) {
        // This UDP relay on the proxy port (PROXY_PORT + 1) is currently a placeholder.
        // Direct UDP traffic from the TUN interface is handled by PinkVpnService directly.
        // We log metrics here for future SOCKS5 UDP relay support if needed.
        ProxyStats.recordDataReceived()
        ProxyStats.recordDataSent()
    }

    fun stop() { 
        try { serverScope.cancel() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        try { proxyDispatcher.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        try { serverSocket?.close(); serverSocket = null } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") } 
        try { udpSocket?.close(); udpSocket = null } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        udpSessions.values.forEach { sess ->
            try { sess.targetSocket.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        }
        udpSessions.clear()
    }

    private val MAX_CONCURRENT_CONNECTIONS = 150
    private val activeConnectionSemaphore = kotlinx.coroutines.sync.Semaphore(MAX_CONCURRENT_CONNECTIONS)

    private suspend fun handleClient(client: Socket) {
        if (!activeConnectionSemaphore.tryAcquire()) {
            try { client.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
            return
        }
        ProxyStats.addConnection()
        try {
            client.soTimeout = 10000; client.tcpNoDelay = true
            val input = client.getInputStream(); val output = client.getOutputStream()
            val headerBuffer = ByteArray(8192); val read = input.read(headerBuffer)
            if (read <= 0) { client.close(); return }
            val header = String(headerBuffer, 0, read, Charsets.UTF_8)
            val firstLine = header.substringBefore("\r").substringBefore("\n").trim()
            if (firstLine.startsWith("CONNECT", ignoreCase = true)) {
                val parts = firstLine.split(" ")
                if (parts.size >= 2) {
                    val hostPort = parts[1]
                    val host = hostPort.substringBefore(":")
                    val portStr = hostPort.substringAfter(":", "443")
                    val port = portStr.toIntOrNull() ?: 443
                    handleHttps(client, host, port, output, input)
                } else {
                    client.close()
                }
            } else { handleHttp(client, header, output, input) }
        } catch (e: Exception) { 
            ProxyStats.addError() 
        } finally { 
            try { client.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
            ProxyStats.removeConnection() 
            activeConnectionSemaphore.release()
        }
    }

    private suspend fun handleHttps(client: Socket, host: String, port: Int, clientOut: OutputStream, clientIn: InputStream) {
        val strategy = BypassConfig.resolveStrategyForHost(host); val config = BypassConfig.getSessionConfig(host, strategy, 100L)
        var connected = false
        var target: Socket? = null
        try {
            val ips = RobustResolver.resolve(host, vpnService); if (ips.isEmpty()) throw Exception("DNS Failed")
            for (ip in ips) {
                val sock = Socket()
                vpnService.protect(sock)
                try {
                    sock.connect(InetSocketAddress(ip, port), 2500)
                    sock.soTimeout = 30000
                    sock.tcpNoDelay = true
                    RobustResolver.recordIpSuccess(ip.hostAddress ?: "")
                    target = sock
                    connected = true
                    break
                } catch (e: Exception) {
                    try { sock.close() } catch (ex: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${ex.message}") }
                    RobustResolver.recordIpFailure(ip.hostAddress ?: "")
                }
            }
            if (!connected || target == null) throw Exception("All IPs failed")
            
            clientOut.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray()); clientOut.flush()
            val targetOut = target.getOutputStream(); val targetIn = target.getInputStream()
            
            val helloBuffer = ByteArray(8192); val helloRead = clientIn.read(helloBuffer)
            if (helloRead > 0) BypassConfig.applyBypass(target, targetOut, helloBuffer, helloRead, config, host)
            
            // Optimize timeouts for the active streaming phase to prevent WebSocket and media drops
            client.soTimeout = 90000
            target.soTimeout = 90000
            
            coroutineScope {
                launch { proxyStream(clientIn, targetOut, { try { target.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") } }, host, false, strategy) }
                launch { proxyStream(targetIn, clientOut, { try { client.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") } }, host, true, strategy) }
            }
        } catch (e: Exception) { 
            BypassConfig.recordFailureForHost(host, strategy, true, vpnService) 
        } finally { 
            try { target?.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") } 
        }
    }

    private suspend fun handleHttp(client: Socket, header: String, clientOut: OutputStream, clientIn: InputStream) {
        var rawHost = ""
        val lines = header.split("\r\n", "\n")
        for (line in lines) {
            if (line.startsWith("Host:", ignoreCase = true)) {
                rawHost = line.substring(5).trim()
                break
            }
        }
        if (rawHost.isEmpty()) rawHost = "google.com"
        val host = rawHost.substringBefore(":")
        val targetPort = if (rawHost.contains(":")) {
            rawHost.substringAfter(":").toIntOrNull() ?: 80
        } else 80

        var target: Socket? = null
        var connected = false
        val strategy = BypassConfig.resolveStrategyForHost(host)
        try {
            val ips = RobustResolver.resolve(host, vpnService); if (ips.isEmpty()) throw Exception("DNS Failed")
            for (ip in ips) {
                val sock = Socket()
                vpnService.protect(sock)
                try {
                    sock.connect(InetSocketAddress(ip, targetPort), 2500)
                    sock.soTimeout = 30000
                    RobustResolver.recordIpSuccess(ip.hostAddress ?: "")
                    target = sock
                    connected = true
                    break
                } catch (e: Exception) {
                    try { sock.close() } catch (ex: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${ex.message}") }
                    RobustResolver.recordIpFailure(ip.hostAddress ?: "")
                }
            }
            if (!connected || target == null) throw Exception("All IPs failed")
            
            // Optimize timeouts for active HTTP streaming
            client.soTimeout = 60000
            target.soTimeout = 60000
            
            val targetOut = target.getOutputStream()
            val config = BypassConfig.getSessionConfig(host, strategy, 100L)
            val headerBytes = header.toByteArray()
            BypassConfig.applyBypass(target, targetOut, headerBytes, headerBytes.size, config, host)
            coroutineScope {
                launch { proxyStream(clientIn, targetOut, { try { target.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") } }, host, false, strategy) }
                launch { proxyStream(target.getInputStream(), clientOut, { try { client.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") } }, host, true, strategy) }
            }
        } catch (e: Exception) {
            Log.e("PinkProxyServer", "Error handling HTTP request for $host", e)
            BypassConfig.recordFailureForHost(host, strategy, true, vpnService)
        } finally { try { target?.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") } }
    }

    private suspend fun proxyStream(input: InputStream, output: OutputStream, onError: () -> Unit, host: String?, isRecv: Boolean, strategy: BypassStrategy?) {
        val buf = getBuffer(16384)
        var successRecorded = false
        try {
            while (true) {
                val r = input.read(buf); if (r <= 0) break
                if (isRecv) ProxyStats.recordDataReceived() else ProxyStats.recordDataSent()
                ProxyStats.addBytes(r.toLong())
                if (isRecv && !successRecorded && host != null && strategy != null) {
                    BypassConfig.recordSuccessForHost(host, strategy)
                    successRecorded = true
                }
                output.write(buf, 0, r)
                output.flush()
            }
            output.flush()
        } catch (e: Exception) {
            // Log less verbosely for common socket closures
            if (e !is java.net.SocketException && e !is java.io.IOException) {
                Log.e("PinkProxyServer", "Error proxying stream to $host", e)
            }
        } finally {
            releaseBuffer(buf)
            onError()
        }
    }
}
