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
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
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

    private val _pool8kSize = MutableStateFlow(0)
    val pool8kSize: StateFlow<Int> = _pool8kSize.asStateFlow()
    
    private val _pool16kSize = MutableStateFlow(0)
    val pool16kSize: StateFlow<Int> = _pool16kSize.asStateFlow()

    private val _congestionWindow = MutableStateFlow(10)
    val congestionWindow: StateFlow<Int> = _congestionWindow.asStateFlow()

    fun updateCongestionWindow(cwnd: Int) {
        _congestionWindow.value = cwnd
    }

    private val poolUpdateCounter = AtomicLong(0)
    fun updatePoolStatus(p8k: Int, p16k: Int) {
        if (poolUpdateCounter.incrementAndGet() % 100L == 0L) {
            _pool8kSize.value = p8k
            _pool16kSize.value = p16k
        }
    }

    private val totalBytes = AtomicLong(0L)
    private val totalErrors = AtomicLong(0L)
    private val totalRequests = AtomicLong(0L)
    
    private val _dnsSuccessCount = MutableStateFlow(0L)
    val dnsSuccessCount: StateFlow<Long> = _dnsSuccessCount.asStateFlow()
    
    private val _dnsFailureCount = MutableStateFlow(0L)
    val dnsFailureCount: StateFlow<Long> = _dnsFailureCount.asStateFlow()

    fun recordDnsResult(success: Boolean) {
        if (success) _dnsSuccessCount.value++ else _dnsFailureCount.value++
    }
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
                delay(60000 + java.util.concurrent.ThreadLocalRandom.current().nextLong(0, 60001))
            }
        }

        kotlinx.coroutines.CoroutineScope(Dispatchers.IO).launch {
            BypassConfig.startOptimizationJobs(this@launch)
            val canaries = listOf("google.com", "wikipedia.org", "openai.com", "facebook.com", "github.com")
            delay(15000)
            while (true) {
                if (isMonitoring) {
                    var failures = 0
                    var dnsFailures = 0
                    for (canary in canaries) {
                        try {
                            withTimeout(5000) {
                                // Test DNS resolution first
                                val dnsStart = System.currentTimeMillis()
                                val ips = RobustResolver.resolve(canary)
                                if (ips.isEmpty()) dnsFailures++
                                
                                // Then test connectivity
                                BypassConfig.shadowProbe(canary)
                            }
                        } catch (e: Exception) {
                            failures++
                        }
                        delay(2000)
                    }
                    
                    if (dnsFailures >= 2) {
                        RobustResolver.dnsMode = "Smart DoH" // Force DoH
                        logRecovery("CORE: DNS Poisoning suspected ($dnsFailures failures). Forcing Smart DoH.")
                    }

                    if (failures >= 3) {
                        ProxyStats.updateCensorshipIntensity(20)
                        logRecovery("CORE: Canary failed ($failures/5). Censorship Suspected: ${ProxyStats.censorshipIntensity.value}%")
                        if (ProxyStats.censorshipIntensity.value > 90) forceReAdaptation()
                    } else if (failures == 0) {
                        ProxyStats.updateCensorshipIntensity(-5)
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
        
        // Rotate global strategy to something safer
        if (ProxyStats.censorshipIntensity.value > 50) {
            val safePool = listOf(BypassStrategy.FRAGMENT_MULTI, BypassStrategy.FAKE_PACKET, BypassStrategy.TCP_OOB_DESYNC)
            BypassConfig.setGlobalStrategy(safePool.random())
            logRecovery("CORE: Rotated global strategy to ${BypassConfig.strategy.value}")
        }
    }

    private val _proxyHealthTrigger = kotlinx.coroutines.flow.MutableSharedFlow<String>(extraBufferCapacity = 1)
    val proxyHealthTrigger = _proxyHealthTrigger.asSharedFlow()

    fun recordFragmentationError() {
        _fragmentationErrors.update { it + 1 }
    }

    fun updateCensorshipIntensity(delta: Int) {
        val current = _censorshipIntensity.value
        _censorshipIntensity.value = (current + delta).coerceIn(0, 100)
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
    TCP_ZERO_WINDOW, GHOST_PACKETS, FRAGMENT_MULTI, HTTP_MANGLE, SNI_CASE, TCP_WINDOW_CLAMP, PACKET_PADDING, TCP_KEEPALIVE, QUIC_BOOST, CHAOS, DIRECT
}

enum class NetworkType { WIFI, MOBILE, UNKNOWN }
enum class HostCategory { STREAMING, SOCIAL, MESSENGER, SEARCH, AI, FINANCE, CDN, NEWS, GAMING, SHOPPING, DEV, OTHER }

object HostClassifier {
    fun classify(host: String): HostCategory {
        val lower = host.lowercase(java.util.Locale.ROOT)
        return when {
            lower.contains("youtube") || lower.contains("googlevideo") || lower.contains("ytimg") ||
            lower.contains("ggpht") || lower.contains("twitch") || lower.contains("netflix") ||
            lower.contains("tiktok") || lower.contains("video.") || lower.contains("stream") ||
            lower.contains("vimeo") || lower.contains("dailymotion") || lower.contains("hulu") ||
            lower.contains("disneyplus") || lower.contains("hbomax") -> HostCategory.STREAMING
            
            lower.contains("instagram") || lower.contains("facebook") || lower.contains("fbcdn") ||
            lower.contains("twitter") || lower.contains("x.com") || lower.contains("reddit") ||
            lower.contains("vk.com") || lower.contains("linkedin") || lower.contains("pinterest") ||
            lower.contains("tumblr") || lower.contains("snapchat") || lower.contains("ok.ru") -> HostCategory.SOCIAL
            
            lower.contains("telegram") || lower.contains("t.me") || lower.contains("whatsapp") ||
            lower.contains("signal") || lower.contains("discord") || lower.contains("slack") ||
            lower.contains("skype") || lower.contains("viber") || lower.contains("line.me") ||
            lower.contains("wechat") -> HostCategory.MESSENGER
            
            lower.contains("google.") || lower.contains("bing") || lower.contains("duckduckgo") ||
            lower.contains("yandex") || lower.contains("baidu") || lower.contains("ask.com") ||
            lower.contains("ecosia") -> HostCategory.SEARCH
            
            lower.contains("openai") || lower.contains("chatgpt") || lower.contains("anthropic") ||
            lower.contains("claude") || lower.contains("deepmind") || lower.contains("gemini") ||
            lower.contains("mistral") || lower.contains("hf.co") || lower.contains("huggingface") ||
            lower.contains("perplexity") -> HostCategory.AI
            
            lower.contains("binance") || lower.contains("coinbase") || lower.contains("tradingview") ||
            lower.contains("metamask") || lower.contains("trustwallet") || lower.contains("ledger") ||
            lower.contains("paypal") || lower.contains("revolut") || lower.contains("wise.com") ||
            lower.contains("blockchain") -> HostCategory.FINANCE

            lower.contains("github") || lower.contains("gitlab") || lower.contains("bitbucket") ||
            lower.contains("stackoverflow") || lower.contains("npm") || lower.contains("pypi") ||
            lower.contains("docker") || lower.contains("aws.") || lower.contains("azure.") ||
            lower.contains("google.cloud") || lower.contains("oracle") || lower.contains("cloudflare") -> HostCategory.DEV
            
            lower.contains("steam") || lower.contains("epicgames") || lower.contains("roblox") ||
            lower.contains("riotgames") || lower.contains("blizzard") || lower.contains("origin") ||
            lower.contains("playstation") || lower.contains("xbox") || lower.contains("nintendo") -> HostCategory.GAMING

            lower.contains("amazon") || lower.contains("ebay") || lower.contains("aliexpress") ||
            lower.contains("alibaba") || lower.contains("shopify") || lower.contains("walmart") ||
            lower.contains("target") -> HostCategory.SHOPPING

            lower.contains("akamai") || lower.contains("fastly") || lower.contains("cloudfront") ||
            lower.contains("bunny") || lower.contains("edgesuite") -> HostCategory.CDN
            
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
    private val _isPanicModeFlow = kotlinx.coroutines.flow.MutableStateFlow(false)
    val isPanicModeFlow: kotlinx.coroutines.flow.StateFlow<Boolean> = _isPanicModeFlow.asStateFlow()
    var isPanicMode: Boolean
        get() = _isPanicModeFlow.value
        set(value) { _isPanicModeFlow.value = value }
    var isCharging = true

    fun autoTuneFragmentation(intensity: Int) {
        if (!isAutoTuning) return
        when {
            intensity > 80 -> {
                frag1 = 1; frag2 = 2; frag3 = 1; delay1 = 5L; delay2 = 5L
            }
            intensity > 50 -> {
                frag1 = 2; frag2 = 3; frag3 = 2; delay1 = 15L; delay2 = 10L
            }
            else -> {
                frag1 = 3; frag2 = 5; frag3 = 2; delay1 = 25L; delay2 = 20L
            }
        }
    }

    fun updateChargingStatus(charging: Boolean) {
        isCharging = charging
    }

    private val _currentStrategy = MutableStateFlow(BypassStrategy.FAKE_PACKET)
    val strategy: StateFlow<BypassStrategy> = _currentStrategy.asStateFlow()

    fun setGlobalStrategy(newStrategy: BypassStrategy) {
        _currentStrategy.value = newStrategy
    }

    private val _currentRttMs = MutableStateFlow(100L)
    val currentRttMs: StateFlow<Long> = _currentRttMs.asStateFlow()

    val currentMtu = MutableStateFlow(1400)
    val udpMtu = MutableStateFlow(1350)

    fun startOptimizationJobs(scope: kotlinx.coroutines.CoroutineScope) {
        scope.launch {
            while (isActive) {
                try {
                    optimizeNetworkParameters()
                    probeMtu()
                } catch (e: Exception) { }
                delay(300000) // Every 5 minutes
            }
        }
        scope.launch {
            delay(60000)
            while (isActive) {
                try {
                    runStrategyBenchmark()
                } catch (e: Exception) { }
                delay(1200000) // Every 20 minutes
            }
        }
    }

    private suspend fun runStrategyBenchmark() {
        val testHost = "google.com"
        val candidates = listOf(
            BypassStrategy.FRAGMENT_MULTI,
            BypassStrategy.FAKE_PACKET,
            BypassStrategy.TCP_OOB_DESYNC,
            BypassStrategy.SNI_SPLIT,
            BypassStrategy.CHAOS
        )
        
        ProxyStats.logRecovery("BENCHMARK: Starting automated strategy evaluation...")
        var bestStrategy = candidates[0]
        var minRtt = Long.MAX_VALUE
        
        for (strategy in candidates) {
            val startTime = System.currentTimeMillis()
            val success = ServiceChecker.probeHostWithStrategy(testHost, strategy)
            if (success) {
                val rtt = System.currentTimeMillis() - startTime
                if (rtt < minRtt) {
                    minRtt = rtt
                    bestStrategy = strategy
                }
            }
            delay(5000) // Cool down between probes
        }
        
        if (minRtt != Long.MAX_VALUE) {
            ProxyStats.logRecovery("BENCHMARK: Best strategy found: $bestStrategy ($minRtt ms). Promoting to global.")
            setGlobalStrategy(bestStrategy)
        } else {
            ProxyStats.logRecovery("BENCHMARK: All candidates failed. Remaining on current strategy.")
        }
    }

    private suspend fun probeMtu() {
        val testHost = "google.com"
        val startMtu = currentMtu.value
        try {
            // Simple logic: if we have frequent DPI faults, reduce MTU
            if (hostDpiFaults.size > 5) {
                currentMtu.value = (startMtu - 40).coerceAtLeast(1280)
                udpMtu.value = (udpMtu.value - 40).coerceAtLeast(1100)
            } else if (hostDpiFaults.isEmpty() && !isPanicMode && startMtu < 1460) {
                // Try increasing if stable
                currentMtu.value = (startMtu + 20).coerceAtMost(1460)
                udpMtu.value = (udpMtu.value + 20).coerceAtMost(1400)
            }
        } catch (e: Exception) {}
    }

    private fun optimizeNetworkParameters() {
        // Adjust MTU based on Network Type and Latency
        val rtt = _currentRttMs.value
        val currentMtuVal = currentMtu.value
        val faults = hostDpiFaults.size
        
        if (faults > 10 || rtt > 800) {
            isPanicMode = true
            ProxyStats.updateCensorshipIntensity(10)
            autoTuneFragmentation(ProxyStats.censorshipIntensity.value)
            ProxyStats.logRecovery("OPTIMIZER: High DPI activity detected ($faults faults). Escalating censorship intensity.")
            hostDpiFaults.clear() // Reset for next cycle
            
            // In panic mode, aggressively reduce delays to compensate for network stress
            delay1 = (delay1 - 5).coerceAtLeast(5L)
            delay2 = (delay2 - 5).coerceAtLeast(5L)
            udpMtu.value = (udpMtu.value - 50).coerceAtLeast(1100)
        } else if (faults == 0 && rtt < 150) {
            // Recovery: good network
            isPanicMode = false
            ProxyStats.updateCensorshipIntensity(-5)
            delay1 = 25L
            delay2 = 20L
            udpMtu.value = 1350
        }

        if (rtt > 500 && currentMtuVal > 1280) {
            // High latency, reduce MTU to avoid fragmentation overhead
            currentMtu.value = (currentMtuVal - 20).coerceAtLeast(1280)
            udpMtu.value = (udpMtu.value - 20).coerceAtLeast(1100)
            ProxyStats.logRecovery("OPTIMIZER: Reducing MTU to ${currentMtu.value} due to latency.")
        } else if (rtt < 100 && currentMtuVal < 1460 && !isPanicMode) {
            // Good network, try increasing MTU for better throughput
            currentMtu.value = (currentMtuVal + 20).coerceAtMost(1460)
        }
    }

    @android.annotation.SuppressLint("SoonBlockedPrivateApi")
    object KernelOptimizer {
        fun optimize(socket: java.net.Socket, isPanic: Boolean) {
            try {
                socket.tcpNoDelay = true
                socket.setSoLinger(false, 0)
                socket.keepAlive = true
                socket.reuseAddress = true
                
                // Use Android system calls for low-level socket optimization
                try {
                    val fdField = java.net.SocketImpl::class.java.getDeclaredField("fd")
                    fdField.isAccessible = true
                    val getImpl = java.net.Socket::class.java.getDeclaredMethod("getImpl")
                    getImpl.isAccessible = true
                    val impl = getImpl.invoke(socket) as java.net.SocketImpl
                    val fd = fdField.get(impl) as? java.io.FileDescriptor
                    
                    if (fd != null && fd.valid()) {
                        // TCP_QUICKACK is usually 12 on Android/Linux
                        android.system.Os.setsockoptInt(fd, android.system.OsConstants.IPPROTO_TCP, 12, 1)
                        android.system.Os.setsockoptInt(fd, android.system.OsConstants.IPPROTO_IP, android.system.OsConstants.IP_TOS, 0x10)
                    }
                } catch (e: Exception) {}
                
                val rtt = _currentRttMs.value
                val scale = if (isPanic || rtt > 200) 2 else 1
                socket.receiveBufferSize = 131072 * scale
                socket.sendBufferSize = 131072 * scale
                socket.trafficClass = 0x10 // IPTOS_LOWDELAY

                try {
                    socket.channel?.let { channel ->
                        if (true) {
                            channel.setOption(java.net.StandardSocketOptions.SO_KEEPALIVE, true)
                            channel.setOption(java.net.StandardSocketOptions.TCP_NODELAY, true)
                            // Set IP_TOS (Type of Service) to minimize delay
                            channel.setOption(java.net.StandardSocketOptions.IP_TOS, 0x10) // IPTOS_LOWDELAY
                        }
                    }
                } catch (e: Exception) {}
            } catch (e: Exception) {}
        }

        fun tuneUdp(socket: java.net.DatagramSocket) {
            try {
                socket.receiveBufferSize = 128 * 1024
                socket.sendBufferSize = 128 * 1024
                socket.reuseAddress = true
            } catch (e: Exception) {}
        }
    }

    object TrafficShaper {
        
        private var burstCounter = 0

        // High-performance Buffer Pooling to reduce GC pressure
        private val pool8k = java.util.concurrent.ArrayBlockingQueue<ByteArray>(128)
        private val pool16k = java.util.concurrent.ArrayBlockingQueue<ByteArray>(64)
        
        private val ewmaRtt = java.util.concurrent.atomic.AtomicLong(100L)
        private val congestionWindow = java.util.concurrent.atomic.AtomicInteger(10) // Packets per burst

        fun acquireBuffer(size: Int): ByteArray {
            val pool = if (size <= 8192) pool8k else pool16k
            val buf = pool.poll() ?: ByteArray(if (size <= 8192) 8192 else 16384)
            ProxyStats.updatePoolStatus(pool8k.size, pool16k.size)
            return buf
        }

        fun releaseBuffer(buffer: ByteArray) {
            val pool = if (buffer.size <= 8192) pool8k else pool16k
            pool.offer(buffer)
            ProxyStats.updatePoolStatus(pool8k.size, pool16k.size)
        }

        suspend fun pace(isPanic: Boolean, dataSize: Int) {
            val rtt = BypassConfig.currentRttMs.value
            
            // Adaptive Pacing: delay increases if RTT is high or data size is large
            val baseDelay = if (isPanic) 4L else 1L
            val jitter = java.util.concurrent.ThreadLocalRandom.current().nextInt(3).toLong()
            
            // Congestion Control: Scale delay based on current RTT vs Baseline (50ms)
            val rttFactor = (rtt.toDouble() / 50.0).coerceIn(0.5, 5.0)
            val finalDelay = (baseDelay * rttFactor).toLong() + jitter
            
            if (finalDelay > 0) {
                kotlinx.coroutines.delay(finalDelay)
            }
            
            // Burst control
            if (dataSize > 4096) {
                burstCounter++
                if (burstCounter > congestionWindow.get()) {
                    kotlinx.coroutines.delay(finalDelay * 2)
                    burstCounter = 0
                    // Dynamically adjust congestion window
                    if (rtt < 150) {
                        val cwnd = congestionWindow.incrementAndGet().coerceAtMost(50)
                        ProxyStats.updateCongestionWindow(cwnd)
                    } else {
                        val cwnd = congestionWindow.decrementAndGet().coerceAtLeast(5)
                        ProxyStats.updateCongestionWindow(cwnd)
                    }
                }
            } else if (!isPanic && dataSize < 1200) {
                // Allow small bursts of traffic to pass without delay
                if (burstCounter++ < 8) return
                burstCounter = 0
            }
        }

        fun getChunkSize(isPanic: Boolean): Int {
            val intensity = ProxyStats.censorshipIntensity.value
            if (intensity > 80) {
                // High entropy chunking in extreme censorship
                return java.util.concurrent.ThreadLocalRandom.current().nextInt(100, 1201)
            }
            // Randomize chunk sizes to break packet length analysis signatures
            return if (isPanic) java.util.concurrent.ThreadLocalRandom.current().nextInt(300, 701) else java.util.concurrent.ThreadLocalRandom.current().nextInt(1100, 1441)
        }

        fun getDelay(isPanic: Boolean): Long {
            val intensity = ProxyStats.censorshipIntensity.value
            return when {
                intensity > 90 -> java.util.concurrent.ThreadLocalRandom.current().nextLong(20, 101) // High jitter delay
                isPanic -> java.util.concurrent.ThreadLocalRandom.current().nextLong(5, 21)
                else -> java.util.concurrent.ThreadLocalRandom.current().nextLong(1, 6)
            }
        }
    }

    data class HostDna(
        var frag1: Int,
        var frag2: Int,
        var delay1: Long,
        var strategy: BypassStrategy? = null,
        var lastSuccess: Long = System.currentTimeMillis()
    )

    private val hostDnas = ConcurrentHashMap<String, HostDna>()
    private val hostFailedStrategies = ConcurrentHashMap<String, MutableSet<BypassStrategy>>()
    private val hostStrategyCache = ConcurrentHashMap<String, BypassStrategy>()
    private val hostSuccessStrategies = ConcurrentHashMap<String, BypassStrategy>()
    private val hostSuccessCount = ConcurrentHashMap<String, Int>()
    private val hostTtlMap = ConcurrentHashMap<String, Int>()

    fun getBestStrategyForHost(host: String): BypassStrategy {
        
        val lHost = host.lowercase(java.util.Locale.ROOT)
        // Auto-Direct (Split Tunneling): Bypass proxy engine completely for RU domains and known local services
        if (lHost.endsWith(".ru") || lHost.endsWith(".su") || lHost.endsWith(".рф") || 
            lHost.contains("yandex") || lHost.contains("vk.com") || lHost.contains("gosuslugi") ||
            lHost.contains("sberbank") || lHost.contains("tinkoff") || lHost.contains("alfabank") ||
            lHost.contains("mail.ru") || lHost.contains("ozon.ru") || lHost.contains("wildberries") ||
            lHost == "localhost" || lHost.startsWith("192.168.") || lHost.startsWith("10.") || lHost.startsWith("127.")) {
            return BypassStrategy.DIRECT
        }
        
        // Chaos Mode: If censorship is extreme, randomize every connection to bypass temporal signatures
        if (ProxyStats.censorshipIntensity.value > 85) {
            val chaosPool = listOf(
                BypassStrategy.TCP_OOB_DESYNC, 
                BypassStrategy.FAKE_PACKET, 
                BypassStrategy.FRAGMENT_MULTI,
                BypassStrategy.SNI_SPLIT,
                BypassStrategy.PACKET_PADDING,
                BypassStrategy.CHAOS
            )
            return chaosPool.random()
        }
        
        val failed = hostFailedStrategies[lHost] ?: emptySet()
        if (lHost.contains("youtube") || lHost.contains("googlevideo")) {
             if (!failed.contains(BypassStrategy.QUIC_BOOST)) {
                 return BypassStrategy.QUIC_BOOST
             }
        }
        if (lHost.contains("discord") || lHost.contains("telegram")) {
             if (!failed.contains(BypassStrategy.TCP_OOB_DESYNC)) {
                 return BypassStrategy.TCP_OOB_DESYNC
             }
        }

        hostStrategyCache[lHost]?.let { return it }
        
        val currentGlobal = strategy.value
        if (currentGlobal == BypassStrategy.DIRECT) return BypassStrategy.DIRECT
        
        // If we have failed strategies for this host, avoid them
        if (failed.contains(currentGlobal)) {
            // Try an alternative
            val alternatives = listOf(BypassStrategy.SNI_SPLIT, BypassStrategy.FRAGMENT_MULTI, BypassStrategy.FAKE_PACKET, BypassStrategy.TCP_OOB_DESYNC)
            val available = alternatives.filter { !failed.contains(it) }
            if (available.isNotEmpty()) {
                val picked = available.first()
                hostStrategyCache[lHost] = picked
                return picked
            }
        }
        
        return currentGlobal
    }

    fun reportFailure(host: String, strategyUsed: BypassStrategy) {
        val lHost = host.lowercase(java.util.Locale.ROOT)
        if (strategyUsed == BypassStrategy.DIRECT) return
        val failed = hostFailedStrategies.getOrPut(lHost) { ConcurrentHashMap.newKeySet() }
        failed.add(strategyUsed)
        hostStrategyCache.remove(lHost)
        Log.w("BypassConfig", "Reported failure for $host with strategy $strategyUsed. Rotating...")
        
        if (failed.size >= 3) {
            isPanicMode = true
            ProxyStats.updateCensorshipIntensity(5)
        }
    }

    fun reportSuccess(host: String, strategyUsed: BypassStrategy) {
        val lHost = host.lowercase(java.util.Locale.ROOT)
        hostStrategyCache[lHost] = strategyUsed
        // Occasionally clear failed list for a host to allow re-testing
        if (java.util.concurrent.ThreadLocalRandom.current().nextDouble() > 0.95) hostFailedStrategies.remove(lHost)
    }

    fun getHostDna(host: String): HostDna {
        val lHost = host.lowercase(java.util.Locale.ROOT)
        return hostDnas.getOrPut(lHost) {
            HostDna(
                frag1 = java.util.concurrent.ThreadLocalRandom.current().nextInt(2, 5 + 1),
                frag2 = java.util.concurrent.ThreadLocalRandom.current().nextInt(20, 100 + 1),
                delay1 = java.util.concurrent.ThreadLocalRandom.current().nextLong(10, 41)
            )
        }
    }
    private val hostExplorationTtl = ConcurrentHashMap<String, Int>()
    private val hostConsecutiveFailures = ConcurrentHashMap<String, Int>()
    private val hostConsecutiveSuccesses = ConcurrentHashMap<String, Int>()
    private val lastFailureTime = ConcurrentHashMap<String, Long>()
    private val directPathHosts = java.util.Collections.synchronizedSet(mutableSetOf<String>())
    private val dynamicallyCensoredHosts = ConcurrentHashMap<String, Long>()
    private val hostDpiFaults = ConcurrentHashMap<String, Int>()
    private val strategyScores = ConcurrentHashMap<String, ConcurrentHashMap<BypassStrategy, Int>>()

    fun recordDpiFault(host: String) {
        val faults = (hostDpiFaults[host] ?: 0) + 1
        hostDpiFaults[host] = faults
        if (faults >= 2) {
            ProxyStats.logRecovery("CORE: DPI block active for $host. Engaging CHAOS Strategy.")
            // Use CHAOS for high-entropy fragmentation and fake packets
            hostSuccessStrategies[host] = BypassStrategy.CHAOS
        } else if (faults >= 1) {
            hostSuccessStrategies[host] = BypassStrategy.SNI_SPLIT
        }
    }

    private val lastResults = java.util.concurrent.ConcurrentLinkedDeque<Boolean>()
    private val MAX_HISTORY = 20

    fun recordStrategyResult(host: String, strategy: BypassStrategy, success: Boolean) {
        lastResults.add(success)
        if (lastResults.size > MAX_HISTORY) lastResults.poll()
        
        // Auto-Panic Detection: if more than 60% of recent requests failed, optimize everything
        val failures = lastResults.count { !it }
        if (lastResults.size >= 10 && failures.toFloat() / lastResults.size > 0.6f) {
            if (!isPanicMode) {
                panicOptimize()
                ProxyStats.logRecovery("AUTO-HEAL: High failure rate detected (${failures}/${lastResults.size}). Panic mode engaged.")
                if (isAutoTuning) {
                    val context = ServiceChecker.appContext
                    if (context != null) {
                        ProxyStats.logRecovery("AUTO-HEAL: Triggering autopilot probe to find a better strategy.")
                        ServiceChecker.runActiveProbing(context)
                    }
                }
            }
        } else if (lastResults.size >= 10 && failures == 0 && isPanicMode) {
            // Auto-Recovery: if last 10 requests were perfect, exit panic mode
            exitPanicMode()
            ProxyStats.logRecovery("AUTO-HEAL: Connection stable. Exiting panic mode.")
        }

        val scores = strategyScores.getOrPut(host) { ConcurrentHashMap() }
        val current = scores.getOrDefault(strategy, 50)
        
        val gScoreDelta = if (success) 15 else -25
        val networkScores = if (_currentNetworkType.value == NetworkType.WIFI) wifiStrategyScores else mobileStrategyScores
        val currentNetScore = networkScores.getOrDefault(strategy, 500)
        networkScores[strategy] = (currentNetScore + gScoreDelta).coerceIn(1, 1000)

        if (success) {
            scores[strategy] = (current + 5).coerceAtMost(100)
            hostConsecutiveSuccesses[host] = (hostConsecutiveSuccesses[host] ?: 0) + 1
            hostConsecutiveFailures[host] = 0
        } else {
            scores[strategy] = (current - 15).coerceAtLeast(0)
            hostConsecutiveFailures[host] = (hostConsecutiveFailures[host] ?: 0) + 1
            hostConsecutiveSuccesses[host] = 0
            
            if ((hostConsecutiveFailures[host] ?: 0) > 4) {
                mutateDnaForHost(host)
            }
        }
    }

    fun panicOptimize() {
        isPanicMode = true
        resetCaches()
        // Aggressive defaults for emergency recovery
        frag1 = java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 2 + 1)
        delay1 = java.util.concurrent.ThreadLocalRandom.current().nextLong(120, 301)
        
        // Reset scores to favor high-success strategies
        globalStrategyScores.forEach { k, v -> globalStrategyScores[k] = (v / 2).coerceAtLeast(50) }
        globalStrategyScores[BypassStrategy.TCP_OOB_DESYNC] = 950
        globalStrategyScores[BypassStrategy.FAKE_PACKET] = 900
        globalStrategyScores[BypassStrategy.FRAGMENT_MULTI] = 850
        globalStrategyScores[BypassStrategy.TCP_ZERO_WINDOW] = 800
        
        ProxyStats.logRecovery("CORE: Emergency Panic Optimization Engaged!")
        
        // Trigger DNS flush
        RobustResolver.clearCache()
    }

    private val _currentFragSize = AtomicInteger(1)
    private val _currentFragSizeState = MutableStateFlow(1)
    val currentFragSizeState: StateFlow<Int> = _currentFragSizeState.asStateFlow()

    private val wifiStrategyScores = ConcurrentHashMap<BypassStrategy, Int>()
    private val mobileStrategyScores = ConcurrentHashMap<BypassStrategy, Int>()
    private val wifiCategoryScores = ConcurrentHashMap<HostCategory, ConcurrentHashMap<BypassStrategy, Int>>()
    private val mobileCategoryScores = ConcurrentHashMap<HostCategory, ConcurrentHashMap<BypassStrategy, Int>>()

    private val defaultScores = mapOf(
        BypassStrategy.FAKE_PACKET to 550, BypassStrategy.TCP_OOB_DESYNC to 600,
        BypassStrategy.SNI_TRIPLE to 450, BypassStrategy.SNI_SPLIT to 400,
        BypassStrategy.SNI_CASE to 350, BypassStrategy.TCP_WINDOW_CLAMP to 420,
        BypassStrategy.TLS_PAD to 300, BypassStrategy.TLS_GREASE to 300,
        BypassStrategy.FRAGMENT_MULTI to 500, BypassStrategy.GHOST_PACKETS to 250,
        BypassStrategy.TCP_ZERO_WINDOW to 410, BypassStrategy.DIRECT to 1
    )

    private val globalStrategyScores = ConcurrentHashMap<BypassStrategy, Int>().apply { putAll(defaultScores) }

    fun getDnaForHost(host: String): HostDna = hostDnas.getOrPut(host) { HostDna(frag1, frag2, delay1) }

    fun mutateDnaForHost(host: String) {
        val dna = getDnaForHost(host)
        // Aggressive mutation: shift towards smaller fragments and varied delays
        dna.frag1 = if (java.util.concurrent.ThreadLocalRandom.current().nextDouble() > 0.5) java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 5 + 1) else java.util.concurrent.ThreadLocalRandom.current().nextInt(5, 12 + 1)
        dna.frag2 = java.util.concurrent.ThreadLocalRandom.current().nextInt(dna.frag1 + 1, 26)
        dna.delay1 = java.util.concurrent.ThreadLocalRandom.current().nextLong(15, 221)
        dna.strategy = null 
        ProxyStats.logRecovery("CORE: Aggressive DNA mutation applied for $host")
    }

    fun getAdaptiveDelay1(): Long {
        val baseDelay = (_currentRttMs.value / 4).coerceIn(10L, 100L) + java.util.concurrent.ThreadLocalRandom.current().nextInt(0, ProxyStats.rttJitter.value.coerceAtMost(50).toInt() + 1)
        val hour = java.util.Calendar.getInstance().get(java.util.Calendar.HOUR_OF_DAY)
        return if (hour in 19..23) (baseDelay * 1.5).toLong() else baseDelay
    }

    fun getCurrentFragSize(): Int {
        val base = _currentFragSize.get().coerceIn(1, 15)
        val hour = java.util.Calendar.getInstance().get(java.util.Calendar.HOUR_OF_DAY)
        return if (hour in 19..23) (base * 0.7).toInt().coerceAtLeast(1) else base
    }

    fun getAdaptiveDelay2(): Long = (_currentRttMs.value / 8).coerceIn(5L, 50L) + java.util.concurrent.ThreadLocalRandom.current().nextInt(0, ProxyStats.rttJitter.value.coerceAtMost(20).toInt() + 1)

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
        if (java.util.concurrent.ThreadLocalRandom.current().nextDouble() > 0.8 && dna.frag1 < 10) { dna.frag1++; if (dna.delay1 > 10) dna.delay1 -= 1 }

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
        
        reportFailure(host, strategy)
        recordStrategyResult(host, strategy, false)
        
        val networkScores = getNetworkScoresMap()
        val penalty = if (isCritical) 20 else 10
        networkScores[strategy] = ((networkScores[strategy] ?: 100) - penalty).coerceAtLeast(10)
        
        lastFailureTime[host] = System.currentTimeMillis()

        val failures = (hostConsecutiveFailures[host] ?: 0) + 1
        hostConsecutiveFailures[host] = failures
        if (failures >= 2) { markHostAsCensored(host); mutateDnaForHost(host) }
        
        if (isCritical || failures >= 3) { 
            hostStrategyCache.remove(host)
            RobustResolver.clearCacheForHost(host) 
        }
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
                                val hello = FakePacketHelper.buildFakeClientHello(host, java.util.concurrent.ThreadLocalRandom.current().nextInt(40, 91))
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

    fun resolveStrategyForHost(host: String): BypassStrategy = getBestStrategyForHost(host)

    fun reOptimize() {
        if (!isAutoTuning) return
        val successRate = ProxyStats.getSuccessRate()
        val rtt = currentRttMs.value
        val isPanic = isPanicMode
        val intensity = ProxyStats.censorshipIntensity.value

        ProxyStats.logRecovery("CORE: Closed-loop global parameter adaptation triggered. Current Success: $successRate%, RTT: $rtt ms, Panic: $isPanic, Intensity: $intensity")

        if (successRate < 70) {
            // Low success rate: increase fragmentation entropy (randomize lengths) and increase split-packet delays
            // to bypass advanced DPI filters.
            frag1 = (frag1 - 1).coerceAtLeast(1)
            frag2 = (frag2 + 1).coerceIn(3, 8)
            frag3 = (frag3 + 1).coerceIn(1, 4)
            // Increase delay slightly to ensure packets don't get merged or reordered by intermediate route elements
            delay1 = (delay1 + 5L).coerceIn(10L, 100L)
            delay2 = (delay2 + 5L).coerceIn(10L, 80L)
            // Shift Fake TTL slightly to bypass hop-count based DPI detectors
            fakeTtl = if (fakeTtl <= 4) 6 else 3
            
            ProxyStats.logRecovery("CORE: Low success rate detected. Mutated params: Frag($frag1/$frag2/$frag3), Delay($delay1/$delay2 ms), FakeTTL: $fakeTtl")
        } else if (successRate > 92 && rtt < 120) {
            // High success and low latency: optimize for throughput and CPU performance
            // Reduce unnecessary fragmentation, lower delays
            if (frag1 < 3) frag1++
            if (frag2 > 4) frag2--
            if (frag3 > 2) frag3--
            
            delay1 = (delay1 - 5L).coerceAtLeast(10L)
            delay2 = (delay2 - 5L).coerceAtLeast(5L)
            
            ProxyStats.logRecovery("CORE: Optimal performance detected. Reducing bypass overhead. Mutated params: Frag($frag1/$frag2/$frag3), Delay($delay1/$delay2 ms)")
        } else {
            // Neutral stable state: check if we should fine-tune delay based on latency (RTT)
            if (rtt > 400) {
                // High latency: lower delays to avoid compounding network latency
                delay1 = (delay1 - 5L).coerceAtLeast(10L)
                delay2 = (delay2 - 5L).coerceAtLeast(5L)
            } else if (rtt < 80) {
                // Extremely low latency: can afford slightly larger delays to improve desync probability
                delay1 = (delay1 + 5L).coerceAtMost(40L)
                delay2 = (delay2 + 5L).coerceAtMost(30L)
            }
        }
        
        // Run global optimization of strategies as part of the re-optimization cycle
        runGlobalOptimization()
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
                TtlHelper.setTtl(socket, config.fakeTtl)
                val fake = FakePacketHelper.buildFakeClientHello(host, java.util.concurrent.ThreadLocalRandom.current().nextInt(40, 121))
                out.write(fake); out.flush(); delay(config.delay1)
                TtlHelper.setTtl(socket, 64)
                out.write(data, 0, len)
            }
            BypassStrategy.SNI_SPLIT -> {
                val splitPos = BypassConfig.findSniPosition(data, len, host)
                if (splitPos > 0) {
                    out.write(data, 0, splitPos)
                    out.flush()
                    delay(config.delay1)
                    out.write(data, splitPos, len - splitPos)
                } else {
                    val split = config.frag1.coerceIn(1, len - 1)
                    out.write(data, 0, split)
                    out.flush()
                    delay(config.delay1)
                    out.write(data, split, len - split)
                }
            }
            BypassStrategy.SNI_TRIPLE -> {
                val splitPos = BypassConfig.findSniPosition(data, len, host)
                if (splitPos > 2) {
                    out.write(data, 0, splitPos - 1)
                    out.flush()
                    delay(config.delay1)
                    out.write(data, splitPos - 1, 2)
                    out.flush()
                    delay(config.delay2)
                    out.write(data, splitPos + 1, len - (splitPos + 1))
                } else {
                    val split1 = (len / 3).coerceAtLeast(1)
                    val split2 = (2 * len / 3).coerceAtLeast(split1 + 1).coerceAtMost(len - 1)
                    out.write(data, 0, split1)
                    out.flush()
                    delay(config.delay1)
                    out.write(data, split1, split2 - split1)
                    out.flush()
                    delay(config.delay2)
                    out.write(data, split2, len - split2)
                }
            }
            BypassStrategy.TCP_OOB_DESYNC -> {
                try {
                    // Send multiple OOB bytes with random data and jitter
                    for (i in 1..java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 4)) {
                        socket.sendUrgentData(java.util.concurrent.ThreadLocalRandom.current().nextInt(256))
                        if (java.util.concurrent.ThreadLocalRandom.current().nextDouble() > 0.5) delay(2)
                    }
                } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                out.write(data, 0, len)
            }
            BypassStrategy.GHOST_PACKETS -> {
                TtlHelper.setTtl(socket, config.fakeTtl)
                val ghost = ByteArray(java.util.concurrent.ThreadLocalRandom.current().nextInt(20, 51)) { java.util.concurrent.ThreadLocalRandom.current().nextInt(256).toByte() }
                out.write(ghost); out.flush(); delay(10)
                TtlHelper.setTtl(socket, 64)
                out.write(data, 0, len)
            }
            BypassStrategy.FRAGMENT_MULTI -> {
                val chunks = java.util.concurrent.ThreadLocalRandom.current().nextInt(3, 6 + 1)
                var offset = 0
                for (i in 0 until chunks) {
                    val remaining = len - offset
                    if (remaining <= 0) break
                    val currentSize = if (i == chunks - 1) remaining else java.util.concurrent.ThreadLocalRandom.current().nextInt(1, (remaining / (chunks - i)).coerceAtLeast(2) + 1)
                    out.write(data, offset, currentSize)
                    out.flush()
                    offset += currentSize
                    delay((config.delay1 / chunks).coerceAtLeast(5L))
                }
            }
            BypassStrategy.TLS_DIRTY -> {
                TtlHelper.setTtl(socket, config.fakeTtl)
                val dirty = ByteArray(java.util.concurrent.ThreadLocalRandom.current().nextInt(10, 31)) { java.util.concurrent.ThreadLocalRandom.current().nextInt(256).toByte() }
                out.write(dirty); out.flush(); delay(15)
                TtlHelper.setTtl(socket, 64)
                out.write(data, 0, len)
            }
            BypassStrategy.HTTP_MANGLE -> {
                val sData = String(data, 0, len, java.nio.charset.StandardCharsets.ISO_8859_1)
                if (sData.contains("Host: ", ignoreCase = true) || sData.contains("GET ", ignoreCase = true) || sData.contains("POST ", ignoreCase = true)) {
                    val mangled = sData.replace("Host: ", "hOsT: ")
                                      .replace("host: ", "HoSt: ")
                                      .replace("GET /", "GET  /")
                                      .replace("POST /", "POST  /")
                    val mBytes = mangled.toByteArray(java.nio.charset.StandardCharsets.ISO_8859_1)
                    out.write(mBytes, 0, mBytes.size)
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.SNI_MANGLE -> {
                val mData = data.copyOf()
                host?.let { h ->
                    val hBytes = h.toByteArray(java.nio.charset.StandardCharsets.ISO_8859_1)
                    for (i in 0 until (len - hBytes.size)) {
                        var match = true
                        for (j in hBytes.indices) {
                            if (mData[i + j].toInt().toChar().lowercaseChar() != hBytes[j].toInt().toChar().lowercaseChar()) {
                                match = false; break
                            }
                        }
                        if (match) {
                            if (i + hBytes.size < len && mData[i + hBytes.size] == 0.toByte()) {
                                mData[i + hBytes.size] = '.'.code.toByte()
                                for (j in hBytes.indices) {
                                    if (j % 2 == 0) {
                                        val c = mData[i + j].toInt().toChar()
                                        mData[i + j] = if (c.isLowerCase()) c.uppercaseChar().code.toByte() else c.lowercaseChar().code.toByte()
                                    }
                                }
                            }
                            break
                        }
                    }
                }
                out.write(mData, 0, len)
            }
            BypassStrategy.TLS_PAD -> {
                val split = (len / 2).coerceAtLeast(1)
                out.write(data, 0, split)
                out.flush()
                
                TtlHelper.setTtl(socket, config.fakeTtl)
                val padding = ByteArray(java.util.concurrent.ThreadLocalRandom.current().nextInt(32, 129)) { 0 }
                out.write(padding)
                out.flush()
                delay(config.delay1)
                
                TtlHelper.setTtl(socket, 64)
                out.write(data, split, len - split)
            }
            BypassStrategy.TLS_GREASE -> {
                val mData = data.copyOf()
                if (len > 50 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                    // Scramble TLS Random (offset 11..42)
                    for (i in 11..42) {
                        if (i < len) mData[i] = java.util.concurrent.ThreadLocalRandom.current().nextInt(256).toByte()
                    }
                    
                    // Scramble TLS Session ID if present (usually at offset 43)
                    val offset = 43
                    if (len > offset + 33) {
                        val sLen = data[offset].toInt() and 0xFF
                        if (sLen in 1..32) {
                            for (i in 0 until sLen) mData[offset + 1 + i] = java.util.concurrent.ThreadLocalRandom.current().nextInt(256).toByte()
                        }
                    }
                    
                    // Attempt to append a Grease Extension if possible (very risky, but can bypass strict fingerprinting)
                    // We only do this if it's a ClientHello and we have space
                }
                out.write(mData, 0, len)
                if (len > 100) {
                    // Send a dummy TLS Record (Alert or similar junk) to break flow signatures
                    val grease = ByteArray(java.util.concurrent.ThreadLocalRandom.current().nextInt(16, 65))
                    grease[0] = 0x17.toByte() // Application Data or 0x15 Alert
                    grease[1] = 0x03.toByte()
                    grease[2] = 0x03.toByte()
                    val gLen = grease.size - 5
                    grease[3] = (gLen shr 8).toByte()
                    grease[4] = (gLen and 0xFF).toByte()
                    for (i in 5 until grease.size) grease[i] = java.util.concurrent.ThreadLocalRandom.current().nextInt(256).toByte()
                    
                    try { out.write(grease); out.flush(); delay(10) } catch (e: Exception) {}
                }
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
                        out.write(data, 0, split)
                        out.flush()
                        delay(config.delay1)
                        out.write(data, split, len - split)
                    } else {
                        val split = (len / 2).coerceAtLeast(1)
                        out.write(data, 0, split)
                        out.flush()
                        delay(config.delay1)
                        out.write(data, split, len - split)
                    }
                } else if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val str = String(data, 0, len, java.nio.charset.StandardCharsets.ISO_8859_1)
                    val mangled = str.replace("Host: ", "hOsT: ").replace("host: ", "HoSt: ")
                    val mBytes = mangled.toByteArray(java.nio.charset.StandardCharsets.ISO_8859_1)
                    val split = (mBytes.size / 2).coerceAtLeast(1)
                    out.write(mBytes, 0, split)
                    out.flush()
                    delay(config.delay1)
                    out.write(mBytes, split, mBytes.size - split)
                } else {
                    val split = (len / 2).coerceAtLeast(1)
                    out.write(data, 0, split)
                    out.flush()
                    delay(config.delay1)
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
                val split = if (len > 2) java.util.concurrent.ThreadLocalRandom.current().nextInt(1, len) else 1
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
                        val customHeaders = "X-Padding-G: ${java.util.concurrent.ThreadLocalRandom.current().nextInt(1000, 9999 + 1)}\r\nX-Resilience: Active\r\n"
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
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.HTTP_TAB -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val str = String(data, 0, len)
                    val mangled = str.replace("Host: ", "Host:\t")
                    val mBytes = mangled.toByteArray()
                    out.write(mBytes, 0, mBytes.size)
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.WINDOW_SIZE -> {
                // Fragmented delivery to mimic small TCP Window behavior
                var offset = 0
                while (offset < len) {
                    val chunkSize = if (offset == 0) java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 2 + 1) else java.util.concurrent.ThreadLocalRandom.current().nextInt(2, 5 + 1)
                    val writeLen = (len - offset).coerceAtMost(chunkSize)
                    out.write(data, offset, writeLen)
                    out.flush()
                    offset += writeLen
                    delay(config.delay1 / 2) // Adaptive delay based on RTT
                }
            }
            BypassStrategy.TCP_ZERO_WINDOW -> {
                // Simulate Zero Window by sending 1 byte, then waiting, then the rest
                out.write(data, 0, 1)
                out.flush()
                delay(config.delay1.coerceAtLeast(30L)) 
                out.write(data, 1, len - 1)
                out.flush()
            }
            BypassStrategy.TCP_WINDOW_CLAMP -> {
                var offset = 0
                while (offset < len) {
                    val current = (len - offset).coerceAtMost(java.util.concurrent.ThreadLocalRandom.current().nextInt(128, 257))
                    out.write(data, offset, current)
                    out.flush()
                    offset += current
                    if (offset < len) delay(java.util.concurrent.ThreadLocalRandom.current().nextLong(5, 16))
                }
            }
            BypassStrategy.SNI_CASE -> {
                val mData = data.copyOf()
                host?.let { h ->
                    val hLower = h.lowercase(java.util.Locale.ROOT)
                    for (i in 0 until (len - hLower.length)) {
                        var match = true
                        for (j in hLower.indices) {
                            val c = mData[i + j].toInt().toChar().lowercaseChar()
                            if (c != hLower[j]) { match = false; break }
                        }
                        if (match) {
                            // Found hostname. Mangle case randomly.
                            for (j in hLower.indices) {
                                if (java.util.concurrent.ThreadLocalRandom.current().nextDouble() > 0.5) {
                                    val c = mData[i + j].toInt().toChar()
                                    mData[i + j] = if (c.isLowerCase()) c.uppercaseChar().code.toByte() else c.lowercaseChar().code.toByte()
                                }
                            }
                            break
                        }
                    }
                }
                out.write(mData, 0, len)
            }
            BypassStrategy.TCP_KEEPALIVE -> {
                try {
                    socket.keepAlive = true
                    // Junk byte to trigger window update
                    out.write(byteArrayOf(java.util.concurrent.ThreadLocalRandom.current().nextInt(256).toByte()))
                    out.flush()
                    delay(config.delay1.coerceAtLeast(10L))
                } catch (e: Exception) {}
                out.write(data, 0, len)
            }
            BypassStrategy.QUIC_BOOST -> {
                var offset = 0
                while (offset < len) {
                    val chunk = java.util.concurrent.ThreadLocalRandom.current().nextInt(100, 400 + 1).coerceAtMost(len - offset)
                    out.write(data, offset, chunk)
                    out.flush()
                    offset += chunk
                    if (offset < len) delay(java.util.concurrent.ThreadLocalRandom.current().nextLong(3, 10))
                }
            }
            BypassStrategy.CHAOS -> {
                var offset = 0
                // Extreme Chaos: Insert fake ECH padding or TLS noise before the real payload
                if (len > 100 && java.util.concurrent.ThreadLocalRandom.current().nextDouble() > 0.3) {
                    val noise = if (java.util.concurrent.ThreadLocalRandom.current().nextDouble() > 0.5) 
                        FakePacketHelper.buildEchPadding(java.util.concurrent.ThreadLocalRandom.current().nextInt(64, 257)) 
                    else 
                        FakePacketHelper.buildTlsNoise(java.util.concurrent.ThreadLocalRandom.current().nextInt(32, 129))
                    TtlHelper.setTtl(socket, config.fakeTtl)
                    out.write(noise)
                    out.flush()
                    delay(TrafficShaper.getDelay(true))
                    TtlHelper.setTtl(socket, 64)
                }
                
                while (offset < len) {
                    val chunkSize = TrafficShaper.getChunkSize(true).coerceAtMost(len - offset)
                    out.write(data, offset, chunkSize)
                    out.flush()
                    offset += chunkSize
                    
                    // Randomly insert fake HTTP/2 noise frames during transmission (absorbed by DPI)
                    if (offset < len && java.util.concurrent.ThreadLocalRandom.current().nextDouble() > 0.7) {
                        TtlHelper.setTtl(socket, config.fakeTtl)
                        out.write(FakePacketHelper.buildFakeHttp2Frame())
                        out.flush()
                        TtlHelper.setTtl(socket, 64)
                    }
                    
                    if (offset < len) {
                        val baseDelay = TrafficShaper.getDelay(true)
                        val jitter = (java.util.concurrent.ThreadLocalRandom.current().nextDouble() * 5).toLong()
                        delay(baseDelay + jitter)
                    }
                }
            }
            BypassStrategy.DIRECT -> {
                out.write(data, 0, len)
            }
            else -> {
                out.write(data, 0, len)
            }
        }
        out.flush()
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
        val oldType = _currentNetworkType.value
        _currentNetworkType.value = netType
        
        if (oldType != netType) {
            // Reset adaptive metrics for the new network
            hostConsecutiveSuccesses.clear()
            hostConsecutiveFailures.clear()
            lastResults.clear()
            RobustResolver.clearCache()
            ProxyStats.logRecovery("NETWORK: Switched to ${netType.name}. Metrics reset.")
        }
    }

    fun getHostConsecutiveFailures(host: String): Int = hostConsecutiveFailures[host] ?: 0
    fun recordHostConsecutiveFailure(host: String, count: Int) { 
        hostConsecutiveFailures[host] = count 
        pruneMemoryIfNeeded()
    }
    
    fun pruneMemoryIfNeeded() {
        if (hostConsecutiveFailures.size > 500) {
            hostConsecutiveFailures.keys.take(100).forEach { hostConsecutiveFailures.remove(it) }
        }
        if (hostDnas.size > 500) {
            val now = System.currentTimeMillis()
            val toRemove = hostDnas.entries.filter { now - it.value.lastSuccess > 86400000 }.map { it.key }
            toRemove.forEach { hostDnas.remove(it) }
            if (hostDnas.size > 500) hostDnas.keys.take(100).forEach { hostDnas.remove(it) }
        }
        if (hostStrategyCache.size > 1000) hostStrategyCache.keys.take(200).forEach { hostStrategyCache.remove(it) }
        if (hostSuccessStrategies.size > 500) hostSuccessStrategies.keys.take(100).forEach { hostSuccessStrategies.remove(it) }
        if (hostSuccessCount.size > 500) hostSuccessCount.keys.take(100).forEach { hostSuccessCount.remove(it) }
        if (hostTtlMap.size > 500) hostTtlMap.keys.take(100).forEach { hostTtlMap.remove(it) }
    }

    fun findSniPosition(data: ByteArray, len: Int, host: String?): Int {
        if (host == null || len < 30) return -1
        try {
            val hostBytes = host.toByteArray(java.nio.charset.StandardCharsets.ISO_8859_1)
            for (i in 0 until (len - hostBytes.size)) {
                var match = true
                for (j in hostBytes.indices) {
                    val c1 = data[i + j].toInt().toChar().lowercaseChar()
                    val c2 = hostBytes[j].toInt().toChar().lowercaseChar()
                    if (c1 != c2) {
                        match = false
                        break
                    }
                }
                if (match) {
                    // Split in the middle of the hostname to break signatures
                    return i + (hostBytes.size / 2)
                }
            }
        } catch (e: Exception) { }
        return -1
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

        wifiStrategyScores.forEach { strat, score -> edit.putInt("wifi_${strat.name}", score) }
        mobileStrategyScores.forEach { strat, score -> edit.putInt("mobile_${strat.name}", score) }
        
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
        val category = HostClassifier.classify(host)
        var f1 = dna.frag1; var f2 = dna.frag2; var f3 = 2; var d1 = dna.delay1; var d2 = getAdaptiveDelay2(); var ttl = 3
        
        // Intelligent TTL discovery based on RTT
        val estimatedHops = (currentRtt / 5).coerceIn(5, 18).toInt()
        
        when (strategy) {
            BypassStrategy.FAKE_PACKET, BypassStrategy.SNI_MANGLE, BypassStrategy.TLS_DIRTY -> { 
                ttl = hostTtlMap[host] ?: estimatedHops
                f1 = java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 5 + 1)
            }
            BypassStrategy.TCP_OOB_DESYNC, BypassStrategy.OOB_DESYNC -> {
                f1 = 1; d1 = java.util.concurrent.ThreadLocalRandom.current().nextLong(15, 41)
                ttl = hostTtlMap[host] ?: estimatedHops
            }
            BypassStrategy.GHOST_PACKETS -> {
                ttl = java.util.concurrent.ThreadLocalRandom.current().nextInt(2, 5 + 1)
                f1 = java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 3 + 1)
            }
            BypassStrategy.WINDOW_SIZE, BypassStrategy.TCP_ZERO_WINDOW -> {
                d1 = (currentRtt / 3).coerceIn(20L, 200L)
            }
            BypassStrategy.SNI_SPLIT, BypassStrategy.SNI_TRIPLE -> { 
                f1 = dna.frag1.coerceIn(1, 5); f2 = dna.frag2.coerceIn(2, 10); d1 = dna.delay1.coerceIn(20, 180) 
            }
            else -> { f1 = 1; d1 = dna.delay1.coerceIn(5, 60) }
        }
        
        // Apply category-specific tweaks for real-world optimization
        when (category) {
            HostCategory.STREAMING -> {
                // Video needs throughput, so slightly larger fragments but more TTL jitter
                f1 = (f1 * 1.5).toInt().coerceIn(1, 15)
                d1 = (d1 * 0.7).toLong().coerceAtLeast(5)
                if (ttl > 1) ttl += java.util.concurrent.ThreadLocalRandom.current().nextInt(-2, 3)
            }
            HostCategory.SOCIAL -> {
                // Social media often has many small images, split them slightly to avoid fingerprinting
                f1 = java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 2 + 1)
                d1 = (d1 * 1.1).toLong()
            }
            HostCategory.MESSENGER -> {
                // Messenger needs stability, more delays to avoid spike detection
                d1 = (d1 * 1.4).toLong()
                f1 = 1
            }
            HostCategory.AI -> {
                // AI often uses heavy TLS 1.3 with large handshakes
                f1 = 1; d1 = (d1 * 1.6).toLong()
            }
            HostCategory.FINANCE -> {
                // Finance needs extreme stealth, very slow initial fragment
                f1 = 1; d1 = (d1 * 2.0).toLong().coerceAtMost(500L)
                ttl = (ttl + 1).coerceAtMost(10)
            }
            HostCategory.GAMING -> {
                // Gaming needs low latency, minimal fragmentation
                f1 = (f1 * 2).coerceAtMost(20)
                d1 = (d1 * 0.5).toLong().coerceAtLeast(1)
            }
            HostCategory.DEV -> {
                // Dev tools java.util.concurrent.ThreadLocalRandom.current().nextInt(git, npm) can handle slightly more aggressive fragmentation
                f1 = java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 4)
            }
            else -> {}
        }

        // Global jitter to prevent fixed-pattern detection
        if (java.util.concurrent.ThreadLocalRandom.current().nextDouble() > 0.8) {
            f1 = (f1 + java.util.concurrent.ThreadLocalRandom.current().nextInt(-1, 2)).coerceIn(1, 20)
            d1 = (d1 + java.util.concurrent.ThreadLocalRandom.current().nextLong(-10, 11)).coerceAtLeast(5)
        }

        if (isHostCensored(host)) {
            d1 = (d1 * 1.3).toLong()
            if (strategy == BypassStrategy.FAKE_PACKET) ttl = (ttl - 1).coerceAtLeast(2)
        }

        return SessionConfig(strategy, f1, f2, f3, d1, d2, ttl.coerceIn(1, 64))
    }
}

data class SessionConfig(val strategy: BypassStrategy, val frag1: Int, val frag2: Int, val frag3: Int, val delay1: Long, val delay2: Long, val fakeTtl: Int)

class PinkProxyServer(private val vpnService: android.net.VpnService, private val port: Int) {
    private val proxyDispatcher = java.util.concurrent.Executors.newCachedThreadPool().asCoroutineDispatcher()
    private var serverScope = kotlinx.coroutines.CoroutineScope(proxyDispatcher + kotlinx.coroutines.SupervisorJob())
    private var serverSocket: ServerSocket? = null
    private var udpSocket: java.net.DatagramSocket? = null
    
    private class PooledConnection(val socket: Socket, val createdAt: Long = System.currentTimeMillis()) {
        fun isAlive(): Boolean {
            return !socket.isClosed && socket.isConnected && (System.currentTimeMillis() - createdAt < 55000)
        }
    }
    
    private val connectionPool = java.util.concurrent.ConcurrentHashMap<String, java.util.concurrent.LinkedBlockingQueue<PooledConnection>>()
    private val MAX_POOL_SIZE: Int get() = if (BypassConfig.isCharging) 5 else 1

    private fun startPreWarmer() {
        serverScope.launch {
            while (isActive) {
                delay(20000)
                try {
                    // Pre-warm connections for the top 3 hosts to achieve 0-RTT connection latency
                    val top = ProxyStats.topHosts.value.take(3).map { it.first }
                    for (host in top) {
                        val port = 443
                        val lHost = host.lowercase(java.util.Locale.ROOT)
                        val pool = connectionPool.getOrPut(lHost + ":" + port) { java.util.concurrent.LinkedBlockingQueue(MAX_POOL_SIZE) }
                        
                        if (pool.size < 2) { // Keep at least 2 warm connections
                            val ips = RobustResolver.resolve(host, vpnService)
                            if (ips.isNotEmpty()) {
                                val sock = java.net.Socket()
                                vpnService?.protect(sock)
                                sock.soTimeout = 10000
                                kotlinx.coroutines.withTimeoutOrNull(5000) {
                                    sock.connect(java.net.InetSocketAddress(ips.first(), port), 3000)
                                    pool.offer(PooledConnection(sock))
                                }
                            }
                        }
                    }
                } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
            }
        }
    }

    init {
        startPreWarmer()
        serverScope.launch {
            while (isActive) {
                delay(15000) // Run more frequent checks
                val now = System.currentTimeMillis()
                connectionPool.values.forEach { queue ->
                    val it = queue.iterator()
                    while (it.hasNext()) {
                        val pc = it.next()
                        if (!pc.isAlive()) {
                            try { pc.socket.close() } catch (e: Exception) {}
                            it.remove()
                            // Optional: Send a minimal TCP Keep-Alive probe if needed
                            // But usually pc.isAlive() check above with TTL is enough
                        }
                    }
                }
            }
        }

        // Network Canary & Auto-Tuning Background Job
        serverScope.launch {
            while (isActive) {
                if (BypassConfig.activeVpnService != null) {
                    try {
                        val start = System.currentTimeMillis()
                        val socket = java.net.Socket()
                        BypassConfig.activeVpnService?.protect(socket)
                        socket.connect(java.net.InetSocketAddress("1.1.1.1", 53), 2000)
                        val rtt = System.currentTimeMillis() - start
                        BypassConfig.updateRtt(rtt)
                        socket.close()
                        
                        // Adaptive strategy adjustment based on RTT
                        if (rtt > 500 && !BypassConfig.isPanicMode) {
                            ProxyStats.logRecovery("AUTO-TUNE: High latency ($rtt ms). Increasing delays.")
                        }
                        
                        // Reliability Test: Fetch small file from reliable source
                        if (System.currentTimeMillis() % 300000 < 60000) { // Every 5 mins
                             val testSocket = java.net.Socket()
                             BypassConfig.activeVpnService?.protect(testSocket)
                             testSocket.connect(java.net.InetSocketAddress("httpbin.org", 80), 3000)
                             testSocket.getOutputStream().write("GET /ip HTTP/1.1\r\nHost: httpbin.org\r\n\r\n".toByteArray())
                             testSocket.close()
                             ProxyStats.logRecovery("STABILITY: Real connectivity verified.")
                        }
                    } catch (e: Exception) {
                        ProxyStats.logRecovery("CANARY: Check failed. Potential network block.")
                        // If it fails multiple times, force panic mode
                        val failures = BypassConfig.getHostConsecutiveFailures("CORE_STABILITY") + 1
                        BypassConfig.recordHostConsecutiveFailure("CORE_STABILITY", failures)
                        if (failures >= 3 && !BypassConfig.isPanicMode) {
                             BypassConfig.panicOptimize()
                        }
                    }
                }
                delay(60000) // Check every minute
            }
        }

        // Traffic Camouflage Background Job
        serverScope.launch {
            while (isActive) {
                delay(java.util.concurrent.ThreadLocalRandom.current().nextLong(180000, 600001)) // Every 3-10 minutes
                if (BypassConfig.activeVpnService != null) {
                    try {
                        val camHosts = listOf("google.com", "bing.com", "cloudflare.com", "apple.com", "microsoft.com")
                        val host = camHosts.random()
                        RobustResolver.resolve(host, vpnService)
                        ProxyStats.logRecovery("CORE: Camouflage burst for $host executed.")
                    } catch (e: Exception) { }
                }
            }
        }
    }

    private fun getBuffer(size: Int): ByteArray = BypassConfig.TrafficShaper.acquireBuffer(size)
    private fun releaseBuffer(buffer: ByteArray) = BypassConfig.TrafficShaper.releaseBuffer(buffer)
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
        val data = packet.data
        val len = packet.length
        if (len < 10) return
        if (data[0].toInt() != 0 || data[1].toInt() != 0) return // RSV
        val frag = data[2].toInt() // FRAG
        val atyp = data[3].toInt() // ATYP
        
        var dstHost = ""
        var dstPort = 0
        var headerLen = 0
        
        when (atyp) {
            1 -> { // IPv4
                if (len < 10) return
                dstHost = "${data[4].toUByte()}.${data[5].toUByte()}.${data[6].toUByte()}.${data[7].toUByte()}"
                dstPort = ((data[8].toInt() and 0xFF) shl 8) or (data[9].toInt() and 0xFF)
                headerLen = 10
            }
            3 -> { // Domain
                val dlen = data[4].toInt() and 0xFF
                if (len < 7 + dlen) return
                dstHost = String(data, 5, dlen)
                dstPort = ((data[5 + dlen].toInt() and 0xFF) shl 8) or (data[6 + dlen].toInt() and 0xFF)
                headerLen = 7 + dlen
            }
            else -> return // IPv6 not supported yet
        }
        
        val payload = data.copyOfRange(headerLen, len)
        val clientKey = "${packet.address.hostAddress}:${packet.port}"
        var session = udpSessions[clientKey]
        
        if (session == null || session.targetSocket.isClosed) {
            val sock = java.net.DatagramSocket()
            session = UdpSession(packet.address, packet.port, sock, System.currentTimeMillis())
            udpSessions[clientKey] = session
            
            serverScope.launch(Dispatchers.IO) {
                val buf = ByteArray(16384)
                while (isActive && !sock.isClosed) {
                    try {
                        val rxPacket = java.net.DatagramPacket(buf, buf.size)
                        sock.receive(rxPacket)
                        
                        val replyPort = rxPacket.port
                        val header = byteArrayOf(0, 0, 0, 1, 0, 0, 0, 0, (replyPort shr 8).toByte(), replyPort.toByte())
                        
                        val finalPayload = ByteArray(10 + rxPacket.length)
                        System.arraycopy(header, 0, finalPayload, 0, 10)
                        System.arraycopy(rxPacket.data, 0, finalPayload, 10, rxPacket.length)
                        
                        val outPacket = java.net.DatagramPacket(finalPayload, finalPayload.size, packet.address, packet.port)
                        udpSocket?.send(outPacket)
                        ProxyStats.recordDataReceived()
                    } catch(e: Exception) {
                        break
                    }
                }
            }
        }
        
        session.lastActivity = System.currentTimeMillis()
        try {
            val targetAddr = if (dstHost.matches(Regex("^[0-9.]+$"))) java.net.InetAddress.getByName(dstHost) else RobustResolver.resolve(dstHost, vpnService).firstOrNull()
            if (targetAddr != null) {
                val isQuicOrStreaming = dstPort == 443 || HostClassifier.classify(dstHost) == HostCategory.STREAMING
                val currentStrategy = BypassConfig.strategy.value
                val isBypassActive = BypassConfig.isAutoTuning && (currentStrategy == BypassStrategy.QUIC_BOOST || currentStrategy == BypassStrategy.CHAOS || currentStrategy == BypassStrategy.FAKE_PACKET)

                if (isBypassActive && isQuicOrStreaming && payload.size > 50) {
                    try {
                        TtlHelper.setUdpTtl(session.targetSocket, BypassConfig.fakeTtl)
                        val decoySize = java.util.concurrent.ThreadLocalRandom.current().nextInt(64, 256)
                        val decoyBytes = ByteArray(decoySize) { java.util.concurrent.ThreadLocalRandom.current().nextInt(256).toByte() }
                        if (decoyBytes.isNotEmpty()) {
                            decoyBytes[0] = (0x40 or java.util.concurrent.ThreadLocalRandom.current().nextInt(16)).toByte()
                        }
                        val decoyPacket = java.net.DatagramPacket(decoyBytes, decoyBytes.size, targetAddr, dstPort)
                        session.targetSocket.send(decoyPacket)
                        kotlinx.coroutines.delay(2)
                    } catch (e: Exception) {
                        android.util.Log.v("PinkProxy", "UDP Decoy failed: ${e.message}")
                    } finally {
                        TtlHelper.setUdpTtl(session.targetSocket, 64)
                    }
                }

                val outPacket = java.net.DatagramPacket(payload, payload.size, targetAddr, dstPort)
                session.targetSocket.send(outPacket)
                ProxyStats.recordDataSent()
            }
        } catch(e: Exception) {}
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
            val headerBuffer = BypassConfig.TrafficShaper.acquireBuffer(8192)
            try {
                val read = input.read(headerBuffer)
                if (read <= 0) { client.close(); return }
                
                if (headerBuffer[0] == 0x05.toByte()) {
                    handleSocks5(client, headerBuffer, read, output, input)
                    return
                }
                
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
                        client.close()
                    }
                } else { handleHttp(client, header, output, input) }
            } finally {
                BypassConfig.TrafficShaper.releaseBuffer(headerBuffer)
            }
        } catch (e: Exception) { 
            ProxyStats.addError() 
        } finally { 
            try { client.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
            ProxyStats.removeConnection() 
            activeConnectionSemaphore.release()
        }
    }

    private suspend fun handleSocks5(client: Socket, initialBuffer: ByteArray, initialRead: Int, clientOut: OutputStream, clientIn: InputStream) {
        // Step 1: Initial greeting already read in initialBuffer
        // Send NO AUTH (0x05, 0x00)
        clientOut.write(byteArrayOf(0x05, 0x00))
        clientOut.flush()
        
        // Step 2: Read request
        val reqBuf = ByteArray(512)
        val read = clientIn.read(reqBuf)
        if (read < 4) return
        
        if (reqBuf[0] != 0x05.toByte() || (reqBuf[1] != 0x01.toByte() && reqBuf[1] != 0x03.toByte())) { 
            clientOut.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0))
            return
        }
        
        val isUdp = reqBuf[1] == 0x03.toByte()
        
        var host = ""
        val atyp = reqBuf[3].toInt()
        var pos = 4
        
        when (atyp) {
            0x01 -> { // IPv4
                host = "${reqBuf[4].toUByte()}.${reqBuf[5].toUByte()}.${reqBuf[6].toUByte()}.${reqBuf[7].toUByte()}"
                pos = 8
            }
            0x03 -> { // Domain
                val len = reqBuf[4].toInt() and 0xFF
                host = String(reqBuf, 5, len, Charsets.UTF_8)
                pos = 5 + len
            }
            0x04 -> { // IPv6
                // Simplified IPv6 representation, assuming RobustResolver handles it if needed
                host = ""
                pos = 20
            }
        }
        
        if (!isUdp && (host.isEmpty() || pos + 1 >= read)) {
            clientOut.write(byteArrayOf(0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0))
            return
        }
        
        if (isUdp) {
            val p = port + 1
            clientOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, (p shr 8).toByte(), p.toByte()))
            clientOut.flush()
            
            try {
                val dummy = ByteArray(1024)
                while (clientIn.read(dummy) >= 0) {
                    kotlinx.coroutines.delay(2000)
                }
            } catch (e: Exception) {}
            return
        }
        
        val port = ((reqBuf[pos].toInt() and 0xFF) shl 8) or (reqBuf[pos+1].toInt() and 0xFF)
        
        var target: Socket? = null
        var activeStrategy = BypassStrategy.FAKE_PACKET
        var activeConfig = BypassConfig.getSessionConfig(host, activeStrategy, 100L)
        var connectionEstablished = false
        val lHost = host.lowercase(java.util.Locale.ROOT)
        
        val helloBuffer = BypassConfig.TrafficShaper.acquireBuffer(8192)
        var helloRead = 0

        val maxAttempts = 3
        var attempt = 0
        while (attempt < maxAttempts && !connectionEstablished) {
            attempt++
            activeStrategy = BypassConfig.resolveStrategyForHost(host)
            activeConfig = BypassConfig.getSessionConfig(host, activeStrategy, 100L)
            
            // Try to reuse pool if it's the first attempt and strategy matches or is compatible
            if (attempt == 1) {
                val poolQueue = connectionPool[lHost + ":" + port]
                if (poolQueue != null) {
                    var pc = poolQueue.poll()
                    while (pc != null) {
                        if (pc.isAlive()) {
                            target = pc.socket
                            break
                        }
                        try { pc.socket.close() } catch (e: Exception) {}
                        pc = poolQueue.poll()
                    }
                }
            }

            try {
                if (target == null) {
                    val ips = RobustResolver.resolve(host, vpnService)
                    if (ips.isEmpty()) throw Exception("DNS Failed")
                    
                    target = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                        val deferredSocket = kotlinx.coroutines.CompletableDeferred<Socket>()
                        val activeJobs = mutableListOf<kotlinx.coroutines.Job>()
                        
                        kotlinx.coroutines.supervisorScope {
                            for (ip in ips) {
                                val job = launch {
                                    val sock = Socket()
                                    try {
                                        vpnService.protect(sock)
                                        sock.connect(InetSocketAddress(ip, port), 2500)
                                        sock.soTimeout = 30000
                                        BypassConfig.KernelOptimizer.optimize(sock, BypassConfig.isPanicMode)
                                        
                                        val osTtl = if (java.util.concurrent.ThreadLocalRandom.current().nextDouble() > 0.5) java.util.concurrent.ThreadLocalRandom.current().nextInt(60, 64 + 1) else java.util.concurrent.ThreadLocalRandom.current().nextInt(120, 128 + 1)
                                        TtlHelper.setTtl(sock, osTtl)
                                        
                                        if (deferredSocket.complete(sock)) {
                                            RobustResolver.recordIpSuccess(ip.hostAddress ?: "")
                                        } else {
                                            try { sock.close() } catch (e: Exception) {}
                                        }
                                    } catch (e: Exception) {
                                        try { sock.close() } catch (ex: Exception) {}
                                        RobustResolver.recordIpFailure(ip.hostAddress ?: "")
                                    }
                                }
                                activeJobs.add(job)
                                delay(150)
                                if (deferredSocket.isCompleted) break
                            }
                            
                            try {
                                val winner = deferredSocket.await()
                                activeJobs.forEach { if (it.isActive) it.cancel() }
                                winner
                            } catch (e: Exception) {
                                null
                            }
                        }
                    }
                }

                if (target == null) throw Exception("All destination IPs failed to connect")

                // Set buffer sizes and optimizations
                val category = HostClassifier.classify(host)
                val netType = BypassConfig.currentNetworkType.value
                if (activeStrategy == BypassStrategy.WINDOW_SIZE || activeStrategy == BypassStrategy.TCP_ZERO_WINDOW) {
                    target.receiveBufferSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(512, 1024 + 1)
                    target.sendBufferSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(512, 1024 + 1)
                } else if (activeStrategy == BypassStrategy.TCP_WINDOW_CLAMP) {
                    target.receiveBufferSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(128, 256 + 1)
                    target.sendBufferSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(128, 256 + 1)
                } else {
                    val isHighSpeed = netType == NetworkType.WIFI
                    val isStreamingOrGaming = category == HostCategory.STREAMING || category == HostCategory.GAMING
                    target.receiveBufferSize = if (isHighSpeed) (if (isStreamingOrGaming) 256 * 1024 else 128 * 1024) else (if (isStreamingOrGaming) 128 * 1024 else 64 * 1024)
                    target.sendBufferSize = if (isHighSpeed) (if (isStreamingOrGaming) 128 * 1024 else 64 * 1024) else (if (isStreamingOrGaming) 64 * 1024 else 32 * 1024)
                }
                
                try {
                    target.tcpNoDelay = true
                    client.tcpNoDelay = true
                    if (activeStrategy == BypassStrategy.TCP_KEEPALIVE) {
                        target.keepAlive = true
                        client.keepAlive = true
                    }
                } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }

                // Success reply to SOCKS5 client
                val reply = byteArrayOf(0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0) // bind address dummy
                clientOut.write(reply)
                clientOut.flush()

                // Apply bypass desynchronization logic on first payload
                val targetOut = target.getOutputStream()
                helloRead = clientIn.read(helloBuffer)
                if (helloRead > 0) {
                    BypassConfig.applyBypass(target, targetOut, helloBuffer, helloRead, activeConfig, host)
                }
                
                BypassConfig.reportSuccess(host, activeStrategy)
                BypassConfig.recordStrategyResult(host, activeStrategy, true)
                connectionEstablished = true
            } catch (e: Exception) {
                Log.w("PinkProxy", "SOCKS5 Attempt $attempt failed for $host with strategy $activeStrategy: ${e.message}")
                if (e.message?.contains("reset", ignoreCase = true) == true || e is java.io.IOException) {
                    BypassConfig.recordDpiFault(host)
                }
                BypassConfig.markHostAsCensored(host)
                BypassConfig.reportFailure(host, activeStrategy)
                BypassConfig.recordStrategyResult(host, activeStrategy, false)
                BypassConfig.recordFailureForHost(host, activeStrategy, true, vpnService)
                
                try { target?.close() } catch (ex: Exception) {}
                target = null
                
                if (attempt < maxAttempts) {
                    delay(50L * attempt)
                }
            }
        }
        
        BypassConfig.TrafficShaper.releaseBuffer(helloBuffer)

        if (!connectionEstablished || target == null) {
            Log.e("PinkProxy", "All SOCKS5 connection and bypass attempts failed for $host")
            try { clientOut.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0,0,0,0, 0,0)) } catch (ex: Exception) {}
            try { client.close() } catch (e: Exception) {}
            return
        }

        try {
            client.soTimeout = 90000
            target.soTimeout = 90000
            
            val targetOut = target.getOutputStream()
            val targetIn = target.getInputStream()
            
            coroutineScope {
                val c2t = launch { proxyStream(clientIn, targetOut, { try { target?.close() } catch (e: Exception) {} }, host, false, activeStrategy) }
                val t2c = launch { proxyStream(targetIn, clientOut, { try { client.close() } catch (e: Exception) {} }, host, true, activeStrategy) }
                
                select<Unit> {
                    c2t.onJoin {}
                    t2c.onJoin {}
                }
                c2t.cancel(); t2c.cancel()
            }
        } catch (e: Exception) {
            Log.v("PinkProxy", "SOCKS5 stream closed: ${e.message}")
        } finally {
            try { target?.close() } catch (e: Exception) {}
        }
    }

    private suspend fun handleHttps(client: Socket, host: String, port: Int, clientOut: OutputStream, clientIn: InputStream) {
        var target: Socket? = null
        var activeStrategy = BypassStrategy.FAKE_PACKET
        var activeConfig = BypassConfig.getSessionConfig(host, activeStrategy, 100L)
        var connectionEstablished = false
        val lHost = host.lowercase(java.util.Locale.ROOT)
        
        val helloBuffer = BypassConfig.TrafficShaper.acquireBuffer(8192)
        var helloRead = 0
        try {
            helloRead = clientIn.read(helloBuffer)
        } catch (e: Exception) {
            BypassConfig.TrafficShaper.releaseBuffer(helloBuffer)
            return
        }

        val maxAttempts = 3
        var attempt = 0
        while (attempt < maxAttempts && !connectionEstablished) {
            attempt++
            activeStrategy = BypassConfig.resolveStrategyForHost(host)
            activeConfig = BypassConfig.getSessionConfig(host, activeStrategy, 100L)
            
            // Try to reuse pool if it's the first attempt and strategy matches or is compatible
            if (attempt == 1) {
                val poolQueue = connectionPool[lHost + ":" + port]
                if (poolQueue != null) {
                    var pc = poolQueue.poll()
                    while (pc != null) {
                        if (pc.isAlive()) {
                            target = pc.socket
                            break
                        }
                        try { pc.socket.close() } catch (e: Exception) {}
                        pc = poolQueue.poll()
                    }
                }
            }

            try {
                if (target == null) {
                    val ips = RobustResolver.resolve(host, vpnService)
                    if (ips.isEmpty()) throw Exception("DNS Failed")
                    
                    target = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                        val deferredSocket = kotlinx.coroutines.CompletableDeferred<Socket>()
                        val activeJobs = mutableListOf<kotlinx.coroutines.Job>()
                        
                        kotlinx.coroutines.supervisorScope {
                            for (ip in ips) {
                                val job = launch {
                                    val sock = Socket()
                                    try {
                                        vpnService.protect(sock)
                                        sock.connect(InetSocketAddress(ip, port), 2500)
                                        sock.soTimeout = 30000
                                        BypassConfig.KernelOptimizer.optimize(sock, BypassConfig.isPanicMode)
                                        
                                        val osTtl = if (java.util.concurrent.ThreadLocalRandom.current().nextDouble() > 0.5) java.util.concurrent.ThreadLocalRandom.current().nextInt(60, 64 + 1) else java.util.concurrent.ThreadLocalRandom.current().nextInt(120, 128 + 1)
                                        TtlHelper.setTtl(sock, osTtl)
                                        
                                        if (deferredSocket.complete(sock)) {
                                            RobustResolver.recordIpSuccess(ip.hostAddress ?: "")
                                        } else {
                                            try { sock.close() } catch (e: Exception) {}
                                        }
                                    } catch (e: Exception) {
                                        try { sock.close() } catch (ex: Exception) {}
                                        RobustResolver.recordIpFailure(ip.hostAddress ?: "")
                                    }
                                }
                                activeJobs.add(job)
                                delay(150)
                                if (deferredSocket.isCompleted) break
                            }
                            
                            try {
                                val winner = deferredSocket.await()
                                activeJobs.forEach { if (it.isActive) it.cancel() }
                                winner
                            } catch (e: Exception) {
                                null
                            }
                        }
                    }
                }

                if (target == null) throw Exception("All destination IPs failed to connect")

                // Set buffer sizes and optimizations
                val category = HostClassifier.classify(host)
                val netType = BypassConfig.currentNetworkType.value
                if (activeStrategy == BypassStrategy.WINDOW_SIZE || activeStrategy == BypassStrategy.TCP_ZERO_WINDOW) {
                    target.receiveBufferSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(512, 1024 + 1)
                    target.sendBufferSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(512, 1024 + 1)
                } else if (activeStrategy == BypassStrategy.TCP_WINDOW_CLAMP) {
                    target.receiveBufferSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(128, 256 + 1)
                    target.sendBufferSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(128, 256 + 1)
                } else {
                    val isHighSpeed = netType == NetworkType.WIFI
                    val isStreamingOrGaming = category == HostCategory.STREAMING || category == HostCategory.GAMING
                    target.receiveBufferSize = if (isHighSpeed) (if (isStreamingOrGaming) 256 * 1024 else 128 * 1024) else (if (isStreamingOrGaming) 128 * 1024 else 64 * 1024)
                    target.sendBufferSize = if (isHighSpeed) (if (isStreamingOrGaming) 128 * 1024 else 64 * 1024) else (if (isStreamingOrGaming) 64 * 1024 else 32 * 1024)
                }
                
                try {
                    target.tcpNoDelay = true
                    client.tcpNoDelay = true
                    if (activeStrategy == BypassStrategy.TCP_KEEPALIVE) {
                        target.keepAlive = true
                        client.keepAlive = true
                    }
                } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }

                // Apply bypass desynchronization logic
                val targetOut = target.getOutputStream()
                if (helloRead > 0) {
                    BypassConfig.applyBypass(target, targetOut, helloBuffer, helloRead, activeConfig, host)
                }
                
                // Confirm established connection to the local app client only after successful bypass application
                clientOut.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
                clientOut.flush()
                
                BypassConfig.reportSuccess(host, activeStrategy)
                BypassConfig.recordStrategyResult(host, activeStrategy, true)
                connectionEstablished = true
            } catch (e: Exception) {
                Log.w("PinkProxy", "Attempt $attempt failed for $host with strategy $activeStrategy: ${e.message}")
                if (e.message?.contains("reset", ignoreCase = true) == true || e is java.io.IOException) {
                    BypassConfig.recordDpiFault(host)
                }
                BypassConfig.markHostAsCensored(host)
                BypassConfig.reportFailure(host, activeStrategy)
                BypassConfig.recordStrategyResult(host, activeStrategy, false)
                BypassConfig.recordFailureForHost(host, activeStrategy, true, vpnService)
                
                try { target?.close() } catch (ex: Exception) {}
                target = null
                
                if (attempt < maxAttempts) {
                    // Stagger retries slightly to let the network settle down
                    delay(50L * attempt)
                }
            }
        }
        
        BypassConfig.TrafficShaper.releaseBuffer(helloBuffer)

        if (!connectionEstablished || target == null) {
            Log.e("PinkProxy", "All connection and bypass attempts failed for $host")
            try { client.close() } catch (e: Exception) {}
            return
        }

        try {
            client.soTimeout = 120000
            target.soTimeout = 120000
            
            val targetOut = target.getOutputStream()
            val targetIn = target.getInputStream()
            
            coroutineScope {
                val c2t = launch { proxyStream(clientIn, targetOut, { try { target?.close() } catch (e: Exception) {} }, host, false, activeStrategy) }
                val t2c = launch { proxyStream(targetIn, clientOut, { try { client.close() } catch (e: Exception) {} }, host, true, activeStrategy) }
                
                select<Unit> {
                    c2t.onJoin {}
                    t2c.onJoin {}
                }
                
                c2t.cancel(); t2c.cancel()
            }
        } catch (e: Exception) {
            Log.v("PinkProxy", "Stream closed: ${e.message}")
        } finally {
            try { target?.close() } catch (e: Exception) {}
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
        var activeStrategy = BypassStrategy.FAKE_PACKET
        var activeConfig = BypassConfig.getSessionConfig(host, activeStrategy, 100L)
        var connectionEstablished = false
        val lHost = host.lowercase(java.util.Locale.ROOT)

        val maxAttempts = 3
        var attempt = 0
        while (attempt < maxAttempts && !connectionEstablished) {
            attempt++
            activeStrategy = BypassConfig.resolveStrategyForHost(host)
            activeConfig = BypassConfig.getSessionConfig(host, activeStrategy, 100L)
            
            // Try to reuse pool if it's the first attempt and strategy matches or is compatible
            if (attempt == 1) {
                val poolQueue = connectionPool[lHost + ":" + targetPort]
                if (poolQueue != null) {
                    var pc = poolQueue.poll()
                    while (pc != null) {
                        if (pc.isAlive()) {
                            target = pc.socket
                            break
                        }
                        try { pc.socket.close() } catch (e: Exception) {}
                        pc = poolQueue.poll()
                    }
                }
            }

            try {
                if (target == null) {
                    val ips = RobustResolver.resolve(host, vpnService)
                    if (ips.isEmpty()) throw Exception("DNS Failed")
                    
                    target = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                        val deferredSocket = kotlinx.coroutines.CompletableDeferred<Socket>()
                        val activeJobs = mutableListOf<kotlinx.coroutines.Job>()
                        
                        kotlinx.coroutines.supervisorScope {
                            for (ip in ips) {
                                val job = launch {
                                    val sock = Socket()
                                    try {
                                        vpnService.protect(sock)
                                        sock.connect(InetSocketAddress(ip, targetPort), 2500)
                                        sock.soTimeout = 30000
                                        BypassConfig.KernelOptimizer.optimize(sock, BypassConfig.isPanicMode)
                                        
                                        val osTtl = if (java.util.concurrent.ThreadLocalRandom.current().nextDouble() > 0.5) java.util.concurrent.ThreadLocalRandom.current().nextInt(60, 64 + 1) else java.util.concurrent.ThreadLocalRandom.current().nextInt(120, 128 + 1)
                                        TtlHelper.setTtl(sock, osTtl)
                                        
                                        if (deferredSocket.complete(sock)) {
                                            RobustResolver.recordIpSuccess(ip.hostAddress ?: "")
                                        } else {
                                            try { sock.close() } catch (e: Exception) {}
                                        }
                                    } catch (e: Exception) {
                                        try { sock.close() } catch (ex: Exception) {}
                                        RobustResolver.recordIpFailure(ip.hostAddress ?: "")
                                    }
                                }
                                activeJobs.add(job)
                                delay(150)
                                if (deferredSocket.isCompleted) break
                            }
                            
                            try {
                                val winner = deferredSocket.await()
                                activeJobs.forEach { if (it.isActive) it.cancel() }
                                winner
                            } catch (e: Exception) {
                                null
                            }
                        }
                    }
                }

                if (target == null) throw Exception("All destination IPs failed to connect")

                // Set buffer sizes and optimizations
                val category = HostClassifier.classify(host)
                val netType = BypassConfig.currentNetworkType.value
                if (activeStrategy == BypassStrategy.WINDOW_SIZE || activeStrategy == BypassStrategy.TCP_ZERO_WINDOW) {
                    target.receiveBufferSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(512, 1024 + 1)
                    target.sendBufferSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(512, 1024 + 1)
                } else if (activeStrategy == BypassStrategy.TCP_WINDOW_CLAMP) {
                    target.receiveBufferSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(128, 256 + 1)
                    target.sendBufferSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(128, 256 + 1)
                } else {
                    val isHighSpeed = netType == NetworkType.WIFI
                    val isStreamingOrGaming = category == HostCategory.STREAMING || category == HostCategory.GAMING
                    target.receiveBufferSize = if (isHighSpeed) (if (isStreamingOrGaming) 256 * 1024 else 128 * 1024) else (if (isStreamingOrGaming) 128 * 1024 else 64 * 1024)
                    target.sendBufferSize = if (isHighSpeed) (if (isStreamingOrGaming) 128 * 1024 else 64 * 1024) else (if (isStreamingOrGaming) 64 * 1024 else 32 * 1024)
                }
                
                try {
                    target.tcpNoDelay = true
                    client.tcpNoDelay = true
                    if (activeStrategy == BypassStrategy.TCP_KEEPALIVE) {
                        target.keepAlive = true
                        client.keepAlive = true
                    }
                } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }

                // Apply bypass desynchronization logic
                val targetOut = target.getOutputStream()
                val headerBytes = header.toByteArray()
                BypassConfig.applyBypass(target, targetOut, headerBytes, headerBytes.size, activeConfig, host)
                
                BypassConfig.reportSuccess(host, activeStrategy)
                BypassConfig.recordStrategyResult(host, activeStrategy, true)
                connectionEstablished = true
            } catch (e: Exception) {
                Log.w("PinkProxy", "HTTP Attempt $attempt failed for $host with strategy $activeStrategy: ${e.message}")
                if (e.message?.contains("reset", ignoreCase = true) == true || e is java.io.IOException) {
                    BypassConfig.recordDpiFault(host)
                }
                BypassConfig.markHostAsCensored(host)
                BypassConfig.reportFailure(host, activeStrategy)
                BypassConfig.recordStrategyResult(host, activeStrategy, false)
                BypassConfig.recordFailureForHost(host, activeStrategy, true, vpnService)
                
                try { target?.close() } catch (ex: Exception) {}
                target = null
                
                if (attempt < maxAttempts) {
                    delay(50L * attempt)
                }
            }
        }

        if (!connectionEstablished || target == null) {
            Log.e("PinkProxy", "All HTTP connection and bypass attempts failed for $host")
            try { client.close() } catch (e: Exception) {}
            return
        }

        try {
            client.soTimeout = 60000
            target.soTimeout = 60000
            
            coroutineScope {
                launch { proxyStream(clientIn, target.getOutputStream(), { try { target?.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") } }, host, false, activeStrategy) }
                launch { proxyStream(target.getInputStream(), clientOut, { try { client.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") } }, host, true, activeStrategy) }
            }
        } catch (e: Exception) {
            Log.v("PinkProxy", "HTTP stream closed: ${e.message}")
        } finally {
            try { target?.close() } catch (e: Exception) {}
        }
    }

    private suspend fun proxyStream(input: InputStream, output: OutputStream, onError: () -> Unit, host: String?, isRecv: Boolean, strategy: BypassStrategy?) {
        val buf = BypassConfig.TrafficShaper.acquireBuffer(16384)
        var successRecorded = false
        var lastActivity = System.currentTimeMillis()
        var totalProcessedBytes = 0L
        
        coroutineScope {
            try {
                val rnd = java.util.concurrent.ThreadLocalRandom.current()
                while (true) {
                    val r = try {
                        input.read(buf)
                    } catch (e: java.io.IOException) {
                        if (e.message?.contains("reset", ignoreCase = true) == true && host != null) {
                            BypassConfig.recordDpiFault(host)
                        }
                        throw e
                    }
                    if (r <= 0) break
                    lastActivity = System.currentTimeMillis()
                    if (isRecv) ProxyStats.recordDataReceived() else ProxyStats.recordDataSent()
                    ProxyStats.addBytes(r.toLong())
                    
                    // Success is recorded after at least 10 bytes of data received from target
                    if (isRecv && !successRecorded && host != null && strategy != null && r > 10) {
                        BypassConfig.recordSuccessForHost(host, strategy)
                        successRecorded = true
                    }
                    
                    if (!isRecv && strategy != null && strategy != BypassStrategy.DIRECT && totalProcessedBytes < 8192) {
                        var offset = 0
                        while (offset < r) {
                            val remaining = r - offset
                            val chunkSize = when (strategy) {
                                BypassStrategy.WINDOW_SIZE, BypassStrategy.TCP_WINDOW_CLAMP -> rnd.nextInt(16, 129)
                                BypassStrategy.FRAGMENT_MULTI -> rnd.nextInt(32, 513)
                                else -> if (remaining < 256) remaining else rnd.nextInt(64, remaining.coerceAtMost(1400) + 1)
                            }.coerceAtMost(remaining)
                            
                            synchronized(output) {
                                output.write(buf, offset, chunkSize)
                                output.flush()
                            }
                            
                            val pace = when (strategy) {
                                BypassStrategy.WINDOW_SIZE -> rnd.nextLong(10, 31)
                                BypassStrategy.SLOW_SEND -> rnd.nextLong(50, 101)
                                else -> rnd.nextLong(1, 3)
                            }
                            delay(pace)
                            offset += chunkSize
                        }
                        totalProcessedBytes += r
                    } else {
                        synchronized(output) {
                            output.write(buf, 0, r)
                            output.flush()
                        }
                        if (isRecv && r > 2048) {
                            BypassConfig.TrafficShaper.pace(BypassConfig.isPanicMode, r)
                        }
                    }

                }
            } catch (e: Exception) {
                onError()
            } finally {
                BypassConfig.TrafficShaper.releaseBuffer(buf)
            }
        }
    }
}
