package com.aistudio.pinkproxy.fresh

import androidx.core.content.edit

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
    
    private val _stabilityScore = MutableStateFlow(100)
    val stabilityScore: StateFlow<Int> = _stabilityScore.asStateFlow()

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
        val count = poolUpdateCounter.incrementAndGet()
        if (count % 20L == 0L || kotlin.math.abs(_pool8kSize.value - p8k) > 5 || kotlin.math.abs(_pool16kSize.value - p16k) > 5) {
            _pool8kSize.value = p8k
            _pool16kSize.value = p16k
        }
    }

    private val recentResults = java.util.Collections.synchronizedList(mutableListOf<Boolean>())
    private val MAX_RESULTS_TRACKING = 100

    fun recordResult(success: Boolean) {
        totalRequests.incrementAndGet()
        if (!success) totalErrors.incrementAndGet()
        
        recentResults.add(success)
        if (recentResults.size > MAX_RESULTS_TRACKING) {
            recentResults.removeAt(0)
        }
        
        updateMetrics()
    }

    private fun updateMetrics() {
        val requests = totalRequests.get()
        if (requests > 0) {
            _successRate.value = (100 - (totalErrors.get() * 100 / requests)).toInt().coerceIn(0, 100)
        }
        
        if (recentResults.isNotEmpty()) {
            val recentSuccesses = recentResults.count { it }
            _stabilityScore.value = (recentSuccesses * 100 / recentResults.size).coerceIn(0, 100)
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
        
        // Calculate Stability Score based on Jitter and Success rate
        val jitter = _rttJitter.value
        val jitterScore = if (jitter < 40) 40 else if (jitter < 120) 25 else 10
        val stabilitySuccessWeight = (rate * 0.6).toInt()
        _stabilityScore.value = (jitterScore + stabilitySuccessWeight).coerceIn(0, 100)
        
        // Calculate Signal Quality (0-100)
        val rtt = BypassConfig.currentRttMs.value
        val rttWeight = if (rtt < 100) 40 else if (rtt < 300) 25 else 10
        val signalSuccessWeight = (rate * 0.6).toInt()
        _signalQuality.value = (rttWeight + signalSuccessWeight).coerceIn(0, 100)
        
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
    TCP_ZERO_WINDOW, GHOST_PACKETS, FRAGMENT_MULTI, HTTP_MANGLE, SNI_CASE, TCP_WINDOW_CLAMP, PACKET_PADDING, TCP_KEEPALIVE, QUIC_BOOST, CHAOS, HTTP_SMUGGLE, TLS_SPLIT_PAD, TLS_FRAG_OOB, HTTP_OBSCURE, DOUBLE_SPLIT, TLS_MIXED_OOB, TLS_HOLE_PUNCH, TCP_OOB_SPLIT, TLS_GHOST_HELLO, TLS_FRAG_RANDOM, TLS_REC_SPLIT, HTTP_LINE_FOLD, QUIC_PAD, TLS_MULTI_FRAG, TCP_SYN_COOKIE_FAKE, TLS_SESSION_RESUME_FAKE, TLS_EXT_SHUFFLE, QUIC_VERSION_NEG_FAKE, HTTP_HOST_SKEW, TLS_ALPN_MANGLE, HTTP_VERB_CASE, TCP_MSS_CLAMP, TLS_EXT_JUNK, HTTP_TE_CHUNKY, TCP_URG_SKEW, TLS_EXT_SKEW, HTTP_AUTH_FAKE, TCP_FAST_RETRANSMIT_SIM, QUIC_INITIAL_FRAG, TLS_SNI_APPEND_JUNK, TCP_SACK_PANIC, TLS_REC_MANGLE, HTTP_PIPE_SIM, TCP_REORDER_SIM, TLS_CLIENT_HELLO_RETRY_SIM, HTTP_COOKIE_SKEW, TCP_ACK_DELAY_SIM, TCP_FAST_OPEN_FAKE, TLS_PADDING_RAND, HTTP_HOST_SPACE, TLS_MULTI_HELLO, HTTP_CHUNKED_MANGLE, TCP_SYN_FLOOD_FAKE, TLS_REHANDSHAKE_FAKE, HTTP_RANGE_SKEW, TCP_RST_FAKE, QUIC_RANDOM_CID, TLS_SNI_SKEW, HTTP_VERSION_SKEW, TCP_TIMESTAMP_MANGLE, UDP_NOISE, TLS_CIPHER_SHUFFLE, HTTP_USER_AGENT_SKEW, TCP_URGENT_RANDOM, DIRECT
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
            lower.contains("perplexity") || lower.contains("grok") || lower.contains("x.ai") -> HostCategory.AI
            
            lower.contains("notion") || lower.contains("evernote") || lower.contains("obsidian") ||
            lower.contains("trello") || lower.contains("asana") || lower.contains("monday.com") -> HostCategory.OTHER
            
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
            lower.contains("target") || lower.contains("rakuten") || lower.contains("etsy") -> HostCategory.SHOPPING

            lower.contains("cnn.com") || lower.contains("bbc") || lower.contains("reuters") ||
            lower.contains("nytimes") || lower.contains("guardian") || lower.contains("bloomberg") ||
            lower.contains("aljazeera") || lower.contains("meduza") || lower.contains("theverge") -> HostCategory.NEWS

            lower.contains("akamai") || lower.contains("fastly") || lower.contains("cloudfront") ||
            lower.contains("bunny") || lower.contains("edgesuite") -> HostCategory.CDN

            lower.contains("binance") || lower.contains("coinbase") || lower.contains("kraken") ||
            lower.contains("metamask") || lower.contains("trustwallet") || lower.contains("ledger") ||
            lower.contains("blockchain") || lower.contains("etoro") || lower.contains("revolut") ||
            lower.contains("wise.com") || lower.contains("payoneer") || lower.contains("paypal") ||
            lower.contains("kucoin") || lower.contains("bybit") || lower.contains("okx") ||
            lower.contains("mexc") || lower.contains("bitget") -> HostCategory.FINANCE

            lower.contains("steam") || lower.contains("epicgames") || lower.contains("roblox") ||
            lower.contains("ubisoft") || lower.contains("blizzard") || lower.contains("nintendo") ||
            lower.contains("playstation") || lower.contains("xbox") || lower.contains("riotgames") ||
            lower.contains("leagueoflegends") || lower.contains("valorant") || lower.contains("fortnite") ||
            lower.contains("minecraft") || lower.contains("twitch") || lower.contains("discord") -> HostCategory.GAMING
            
            else -> HostCategory.OTHER
        }
    }
}

object BypassConfig {
    @Volatile var activeVpnService: android.net.VpnService? = null
    
    fun isHostDirect(host: String): Boolean {
        val lHost = host.lowercase(java.util.Locale.ROOT)
        return lHost.endsWith(".ru") || lHost.endsWith(".su") || lHost.endsWith(".рф") || 
               lHost.contains("yandex") || lHost.contains("vk.com") || lHost.contains("gosuslugi") ||
               lHost.contains("sberbank") || lHost.contains("tinkoff") || lHost.contains("alfabank") ||
               lHost.contains("mail.ru") || lHost.contains("ozon.ru") || lHost.contains("wildberries") ||
               lHost == "localhost" || lHost.startsWith("192.168.") || lHost.startsWith("10.") || lHost.startsWith("127.")
    }

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
    private val _isChargingFlow = kotlinx.coroutines.flow.MutableStateFlow(true)
    val isChargingFlow: kotlinx.coroutines.flow.StateFlow<Boolean> = _isChargingFlow.asStateFlow()
    var isCharging: Boolean
        get() = _isChargingFlow.value
        set(value) { _isChargingFlow.value = value }
    var isDiagnosticMode = false
    private val networkStrategyMemory = ConcurrentHashMap<NetworkType, BypassStrategy>()

    fun autoTuneFragmentation(intensity: Int) {
        if (!isAutoTuning) return
        
        val rtt = BypassConfig.currentRttMs.value.coerceAtLeast(1)
        val rttMultiplier = (rtt.toDouble() / 150.0).coerceIn(0.5, 3.0)
        
        when {
            intensity > 95 -> {
                frag1 = 1; frag2 = 1; frag3 = 1
                delay1 = (150L * rttMultiplier).toLong()
                delay2 = (120L * rttMultiplier).toLong()
                if (strategy.value != BypassStrategy.TCP_URG_SKEW && strategy.value != BypassStrategy.CHAOS) {
                    setGlobalStrategy(BypassStrategy.TCP_URG_SKEW)
                }
            }
            intensity > 90 -> {
                frag1 = 1; frag2 = 1; frag3 = 1
                delay1 = (100L * rttMultiplier).toLong()
                delay2 = (80L * rttMultiplier).toLong()
                if (strategy.value != BypassStrategy.CHAOS && strategy.value != BypassStrategy.QUIC_INITIAL_FRAG) {
                    setGlobalStrategy(BypassStrategy.CHAOS)
                }
            }
            intensity > 75 -> {
                frag1 = 1; frag2 = 2; frag3 = 1
                delay1 = (60L * rttMultiplier).toLong()
                delay2 = (45L * rttMultiplier).toLong()
                if (strategy.value == BypassStrategy.DIRECT) setGlobalStrategy(BypassStrategy.FAKE_PACKET)
            }
            intensity > 45 -> {
                frag1 = 2; frag2 = 2; frag3 = 1
                delay1 = (40L * rttMultiplier).toLong()
                delay2 = (30L * rttMultiplier).toLong()
                if (strategy.value == BypassStrategy.DIRECT) setGlobalStrategy(BypassStrategy.SNI_SPLIT)
            }
            intensity > 20 -> {
                frag1 = 2; frag2 = 3; frag3 = 1
                delay1 = (25L * rttMultiplier).toLong()
                delay2 = (20L * rttMultiplier).toLong()
            }
            else -> {
                frag1 = 3; frag2 = 5; frag3 = 2
                delay1 = (15L * rttMultiplier).toLong()
                delay2 = (10L * rttMultiplier).toLong()
            }
        }
        
        // Proactive Strategy Rotation: if success rate is low even after tuning
        if (ProxyStats.successRate.value < 50 && intensity > 50) {
            val best = getGlobalBestStrategy()
            if (best != strategy.value) {
                setGlobalStrategy(best)
                ProxyStats.logRecovery("AUTO-TUNE: Low success rate, rotating to best known: ${best.name}")
            }
        }
    }

    fun updateChargingStatus(charging: Boolean) {
        isCharging = charging
    }

    private val _currentStrategy = MutableStateFlow(BypassStrategy.FAKE_PACKET)
    val strategy: StateFlow<BypassStrategy> = _currentStrategy.asStateFlow()

    fun setGlobalStrategy(newStrategy: BypassStrategy) {
        if (_currentStrategy.value != newStrategy) {
            _currentStrategy.value = newStrategy
            networkStrategyMemory[_currentNetworkType.value] = newStrategy
        }
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
                    probeTopHosts()
                    checkDnsHealth()
                    performDeepHealthProbe()
                    autoCleanup()
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
        scope.launch {
            while (isActive) {
                if (ProxyStats.censorshipIntensity.value > 80) {
                    rotateGlobalStrategy()
                }
                delay(if (isPanicMode) 120000 else 600000) // 2 or 10 minutes
            }
        }
    }

    fun rotateGlobalStrategy() {
        val pools = listOf(
            BypassStrategy.SNI_SPLIT, BypassStrategy.TLS_DIRTY, BypassStrategy.FRAGMENT_MULTI,
            BypassStrategy.TLS_MIXED_OOB, BypassStrategy.TCP_OOB_SPLIT, BypassStrategy.TLS_GHOST_HELLO,
            BypassStrategy.TLS_FRAG_RANDOM, BypassStrategy.TLS_REC_SPLIT, BypassStrategy.TLS_MULTI_FRAG,
            BypassStrategy.TLS_EXT_SHUFFLE, BypassStrategy.HTTP_HOST_SKEW, BypassStrategy.CHAOS,
            BypassStrategy.TLS_ALPN_MANGLE, BypassStrategy.HTTP_VERB_CASE, BypassStrategy.TCP_MSS_CLAMP,
            BypassStrategy.TLS_CLIENT_HELLO_RETRY_SIM, BypassStrategy.HTTP_COOKIE_SKEW,
            BypassStrategy.TCP_ACK_DELAY_SIM, BypassStrategy.TCP_SACK_PANIC
        )
        val current = strategy.value
        val next = pools.filter { it != current }.random()
        ProxyStats.logRecovery("AUTO-ROTATION: Rotating strategy to ${next.name} due to high censorship.")
        setGlobalStrategy(next)
    }

    suspend fun runStrategyBenchmark() {
        val testHosts = listOf("google.com", "wikipedia.org", "github.com", "chatgpt.com")
        val candidates = listOf(
            BypassStrategy.FRAGMENT_MULTI,
            BypassStrategy.FAKE_PACKET,
            BypassStrategy.TCP_OOB_DESYNC,
            BypassStrategy.SNI_SPLIT,
            BypassStrategy.TLS_GHOST_HELLO,
            BypassStrategy.TLS_FRAG_RANDOM,
            BypassStrategy.TLS_REC_SPLIT,
            BypassStrategy.HTTP_LINE_FOLD,
            BypassStrategy.CHAOS,
            BypassStrategy.TLS_CLIENT_HELLO_RETRY_SIM,
            BypassStrategy.TCP_ACK_DELAY_SIM,
            BypassStrategy.TLS_CIPHER_SHUFFLE,
            BypassStrategy.HTTP_USER_AGENT_SKEW,
            BypassStrategy.TCP_URGENT_RANDOM,
            BypassStrategy.UDP_NOISE
        )
        
        ProxyStats.logRecovery("BENCHMARK: Starting automated strategy evaluation on fallback hosts...")
        var bestStrategy = candidates[0]
        var minRtt = Long.MAX_VALUE
        
        for (strategy in candidates) {
            val startTime = System.currentTimeMillis()
            var success = false
            for (host in testHosts) {
                if (ServiceChecker.probeHostWithStrategy(host, strategy)) {
                    success = true
                    break
                }
            }
            if (success) {
                val rtt = System.currentTimeMillis() - startTime
                if (rtt < minRtt) {
                    minRtt = rtt
                    bestStrategy = strategy
                }
            }
            delay(3000) // Cool down between probes
        }
        
        if (minRtt != Long.MAX_VALUE) {
            ProxyStats.logRecovery("BENCHMARK: Best strategy found: $bestStrategy ($minRtt ms). Promoting to global.")
            setGlobalStrategy(bestStrategy)
        } else {
            ProxyStats.logRecovery("BENCHMARK: All candidates failed. Remaining on current strategy.")
        }
    }

    private suspend fun probeTopHosts() {
        // Find top 3 hosts by traffic
        val top = ProxyStats.topHosts.value.take(3)
        if (top.isEmpty()) return
        
        ProxyStats.logRecovery("AUTO-PROBE: Testing top ${top.size} hosts for optimal strategies...")
        
        for (hostEntry in top) {
            val host = hostEntry.first
            // Only probe if we don't have a stable strategy already
            if (hostStrategyCache[host] != null && hostFailedStrategies[host]?.isEmpty() == true) continue
            
            // Try to find a working strategy by doing a tiny HEAD request or just a TCP connect
            val candidates = listOf(BypassStrategy.SNI_SPLIT, BypassStrategy.TLS_DIRTY, BypassStrategy.FRAGMENT_MULTI, BypassStrategy.FAKE_PACKET)
            for (strategy in candidates) {
                try {
                    withTimeout(5000) {
                        val socket = Socket()
                        socket.connect(InetSocketAddress(host, 443), 2000)
                        socket.close()
                    }
                    ProxyStats.logRecovery("AUTO-PROBE: Strategy $strategy verified for $host")
                    hostStrategyCache[host] = strategy
                    break
                } catch (e: Exception) {
                    // Try next strategy
                }
            }
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

    fun getCurrentRttMs(): Long = _currentRttMs.value
    
    fun offsetMtu(delta: Int) {
        currentMtu.value = (currentMtu.value + delta).coerceIn(1200, 1460)
        udpMtu.value = (udpMtu.value + delta).coerceIn(1100, 1400)
    }

    fun enterPanicMode() {
        if (!isPanicMode) {
            isPanicMode = true
            ProxyStats.logRecovery("WATCHDOG: ENTERING PANIC MODE.")
            optimizeNetworkParameters()
        }
    }

    fun optimizeNetworkParameters() {
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
            
            // Wipe failed cache to allow re-probing under panic rules
            if (faults > 20) {
                hostFailedStrategies.clear()
                hostStrategyCache.clear()
                blockQuic = true
                RobustResolver.clearCache()
                ProxyStats.logRecovery("OPTIMIZER: SEVERE DPI PRESSURE. Full cache wipe and QUIC blocking enabled.")
            }
        } else if (faults == 0 && rtt < 150) {
            // Recovery: good network
            if (isPanicMode) {
                ProxyStats.logRecovery("OPTIMIZER: Network stabilized, scaling back panic parameters")
            }
            isPanicMode = false
            ProxyStats.updateCensorshipIntensity(-5)
            
            // Slowly increase MTU towards optimal
            if (currentMtuVal < 1460) {
                currentMtu.value = (currentMtuVal + 20).coerceAtMost(1460)
                udpMtu.value = (udpMtu.value + 20).coerceAtMost(1400)
            }
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

    private suspend fun performDeepHealthProbe() {
        val testHosts = listOf("1.1.1.1", "dns.google", "cloudflare.com", "github.com")
        var overallSuccess = 0
        for (host in testHosts) {
            try {
                val socket = java.net.Socket()
                socket.connect(java.net.InetSocketAddress(host, 443), 5000)
                socket.close()
                overallSuccess++
            } catch (e: Exception) {}
            delay(1000)
        }
        
        if (overallSuccess == 0) {
            ProxyStats.logRecovery("HEALTH: Deep probe failed for all major CDNs. Network may be severely restricted.")
            ProxyStats.updateCensorshipIntensity(10)
            if (!isPanicMode) {
                isPanicMode = true
                optimizeNetworkParameters()
                probeMtu()
            }
        } else if (overallSuccess < 3) {
            ProxyStats.logRecovery("HEALTH: Deep probe degraded ($overallSuccess/${testHosts.size}). Increasing intensity.")
            ProxyStats.updateCensorshipIntensity(5)
        } else {
            ProxyStats.logRecovery("HEALTH: Deep probe passed ($overallSuccess/${testHosts.size}). Network healthy.")
        }
    }

    private suspend fun checkDnsHealth() {
        try {
            // Test if current best DoH is working
            val testHost = "google.com"
            val results = RobustResolver.resolve(testHost)
            if (results.isEmpty()) {
                ProxyStats.logRecovery("DNS: Health check failed for $testHost. Forcing DNS cache reset.")
                RobustResolver.clearCache()
                // If it keeps failing, maybe DNS is poisoned/blocked, escalation needed
                ProxyStats.updateCensorshipIntensity(5)
            } else {
                ProxyStats.logRecovery("DNS: Health check OK (${results.size} IPs found)")
            }
        } catch (e: Exception) {
            ProxyStats.logRecovery("DNS: Health check error: ${e.message}")
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
                    var pfd: android.os.ParcelFileDescriptor? = null
                    val fd: java.io.FileDescriptor? = if (android.os.Build.VERSION.SDK_INT < 28) {
                        try {
                            val fdField = java.net.SocketImpl::class.java.getDeclaredField("fd")
                            fdField.isAccessible = true
                            val getImpl = java.net.Socket::class.java.getDeclaredMethod("getImpl")
                            getImpl.isAccessible = true
                            val impl = getImpl.invoke(socket) as java.net.SocketImpl
                            fdField.get(impl) as? java.io.FileDescriptor
                        } catch (e: Exception) { null }
                    } else {
                        pfd = android.os.ParcelFileDescriptor.fromSocket(socket)
                        pfd.fileDescriptor
                    }

                    if (fd != null && fd.valid()) {
                        // TCP_QUICKACK is usually 12 on Android/Linux
                        android.system.Os.setsockoptInt(fd, android.system.OsConstants.IPPROTO_TCP, 12, 1)
                        android.system.Os.setsockoptInt(fd, android.system.OsConstants.IPPROTO_IP, android.system.OsConstants.IP_TOS, 0x10)
                        
                        // TCP_USER_TIMEOUT is 18. Set to 10 seconds to detect network drops fast and recover instantly
                        try {
                            android.system.Os.setsockoptInt(fd, android.system.OsConstants.IPPROTO_TCP, 18, 10000)
                            // SO_KEEPALIVE
                            android.system.Os.setsockoptInt(fd, android.system.OsConstants.SOL_SOCKET, android.system.OsConstants.SO_KEEPALIVE, 1)
                            // SO_RCVBUF / SO_SNDBUF expansion
                            android.system.Os.setsockoptInt(fd, android.system.OsConstants.SOL_SOCKET, android.system.OsConstants.SO_RCVBUF, 524288)
                            android.system.Os.setsockoptInt(fd, android.system.OsConstants.SOL_SOCKET, android.system.OsConstants.SO_SNDBUF, 524288)
                        } catch (ex: Exception) {}
                    }
                    try { pfd?.close() } catch (e: Exception) {}
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

        // Lock-free High-performance Buffer Pooling to reduce GC pressure and lock contention
        private val pool8k = java.util.concurrent.ConcurrentLinkedQueue<ByteArray>()
        private val pool16k = java.util.concurrent.ConcurrentLinkedQueue<ByteArray>()
        private val size8k = java.util.concurrent.atomic.AtomicInteger(0)
        private val size16k = java.util.concurrent.atomic.AtomicInteger(0)
        
        private val ewmaRtt = java.util.concurrent.atomic.AtomicLong(100L)
        private val congestionWindow = java.util.concurrent.atomic.AtomicInteger(10) // Packets per burst

        fun acquireBuffer(size: Int): ByteArray {
            if (size <= 8192) {
                val buf = pool8k.poll()
                if (buf != null) {
                    size8k.decrementAndGet()
                    ProxyStats.updatePoolStatus(size8k.get(), size16k.get())
                    return buf
                }
                return ByteArray(8192)
            } else {
                val buf = pool16k.poll()
                if (buf != null) {
                    size16k.decrementAndGet()
                    ProxyStats.updatePoolStatus(size8k.get(), size16k.get())
                    return buf
                }
                return ByteArray(16384)
            }
        }

        fun releaseBuffer(buffer: ByteArray) {
            if (buffer.size <= 8192) {
                if (size8k.get() < 128) {
                    pool8k.offer(buffer)
                    size8k.incrementAndGet()
                }
            } else {
                if (size16k.get() < 64) {
                    pool16k.offer(buffer)
                    size16k.incrementAndGet()
                }
            }
            ProxyStats.updatePoolStatus(size8k.get(), size16k.get())
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

    fun getGlobalBestStrategy(): BypassStrategy {
        val scores = globalStrategyScores
        return scores.maxByOrNull { it.value }?.key ?: BypassStrategy.TCP_OOB_DESYNC
    }

    fun getBestStrategyForHost(host: String): BypassStrategy {
        if (BypassConfig.isHostDirect(host)) {
            return BypassStrategy.DIRECT
        }
        val lHost = host.lowercase(java.util.Locale.ROOT)
        
        // Chaos Mode: If censorship is extreme, randomize every connection to bypass temporal signatures
        if (ProxyStats.censorshipIntensity.value > 85) {
            val chaosPool = listOf(
                BypassStrategy.TCP_OOB_DESYNC, 
                BypassStrategy.FAKE_PACKET, 
                BypassStrategy.FRAGMENT_MULTI,
                BypassStrategy.SNI_SPLIT,
                BypassStrategy.PACKET_PADDING,
                BypassStrategy.CHAOS,
                BypassStrategy.TLS_MIXED_OOB,
                BypassStrategy.DOUBLE_SPLIT,
                BypassStrategy.TLS_GHOST_HELLO,
                BypassStrategy.TLS_HOLE_PUNCH,
                BypassStrategy.TCP_OOB_SPLIT,
                BypassStrategy.TLS_FRAG_RANDOM,
                BypassStrategy.TLS_REC_SPLIT,
                BypassStrategy.HTTP_LINE_FOLD,
                BypassStrategy.QUIC_PAD,
                BypassStrategy.TLS_MULTI_FRAG,
                BypassStrategy.TCP_SYN_COOKIE_FAKE,
                BypassStrategy.TLS_SESSION_RESUME_FAKE,
                BypassStrategy.TLS_EXT_SHUFFLE,
                BypassStrategy.QUIC_VERSION_NEG_FAKE,
                BypassStrategy.HTTP_HOST_SKEW,
                BypassStrategy.TLS_ALPN_MANGLE,
                BypassStrategy.HTTP_VERB_CASE,
                BypassStrategy.TCP_MSS_CLAMP,
                BypassStrategy.TLS_EXT_JUNK,
                BypassStrategy.HTTP_TE_CHUNKY,
                BypassStrategy.TCP_URG_SKEW,
                BypassStrategy.TLS_EXT_SKEW,
                BypassStrategy.HTTP_AUTH_FAKE,
                BypassStrategy.TCP_FAST_RETRANSMIT_SIM,
                BypassStrategy.QUIC_INITIAL_FRAG,
                BypassStrategy.TLS_SNI_APPEND_JUNK,
                BypassStrategy.TCP_SACK_PANIC,
                BypassStrategy.TLS_REC_MANGLE,
                BypassStrategy.HTTP_PIPE_SIM,
                BypassStrategy.TCP_REORDER_SIM,
                BypassStrategy.TLS_CLIENT_HELLO_RETRY_SIM,
                BypassStrategy.HTTP_COOKIE_SKEW,
                BypassStrategy.TCP_FAST_OPEN_FAKE,
                BypassStrategy.TLS_PADDING_RAND,
                BypassStrategy.HTTP_HOST_SPACE,
                BypassStrategy.TLS_MULTI_HELLO,
                BypassStrategy.HTTP_CHUNKED_MANGLE,
                BypassStrategy.TCP_SYN_FLOOD_FAKE,
                BypassStrategy.TLS_REHANDSHAKE_FAKE,
                BypassStrategy.HTTP_RANGE_SKEW,
                BypassStrategy.TCP_RST_FAKE,
                BypassStrategy.QUIC_RANDOM_CID,
                BypassStrategy.TLS_SNI_SKEW,
                BypassStrategy.HTTP_VERSION_SKEW,
                BypassStrategy.TCP_TIMESTAMP_MANGLE,
                BypassStrategy.UDP_NOISE,
                BypassStrategy.TLS_CIPHER_SHUFFLE,
                BypassStrategy.HTTP_USER_AGENT_SKEW,
                BypassStrategy.TCP_URGENT_RANDOM
            )
            return chaosPool.random()
        }
        
        val failed = hostFailedStrategies[lHost] ?: emptySet()
        if (lHost.contains("youtube") || lHost.contains("googlevideo")) {
             if (!failed.contains(BypassStrategy.TLS_FRAG_OOB)) {
                 return BypassStrategy.TLS_FRAG_OOB
             }
             if (!failed.contains(BypassStrategy.TLS_SPLIT_PAD)) {
                 return BypassStrategy.TLS_SPLIT_PAD
             }
             if (!failed.contains(BypassStrategy.QUIC_BOOST)) {
                 return BypassStrategy.QUIC_BOOST
             }
             if (!failed.contains(BypassStrategy.TLS_FRAG_RANDOM)) {
                 return BypassStrategy.TLS_FRAG_RANDOM
             }
        }
        if (lHost.contains("discord") || lHost.contains("telegram")) {
             if (!failed.contains(BypassStrategy.TCP_OOB_DESYNC)) {
                 return BypassStrategy.TCP_OOB_DESYNC
             }
        }
        
        val category = HostClassifier.classify(lHost)
        when (category) {
            HostCategory.FINANCE -> {
                if (!failed.contains(BypassStrategy.TLS_PAD)) return BypassStrategy.TLS_PAD
                if (!failed.contains(BypassStrategy.SNI_MANGLE)) return BypassStrategy.SNI_MANGLE
            }
            HostCategory.GAMING -> {
                if (!failed.contains(BypassStrategy.QUIC_BOOST)) return BypassStrategy.QUIC_BOOST
                if (!failed.contains(BypassStrategy.TCP_WINDOW_CLAMP)) return BypassStrategy.TCP_WINDOW_CLAMP
                if (!failed.contains(BypassStrategy.UDP_NOISE)) return BypassStrategy.UDP_NOISE
            }
            else -> {}
        }

        hostStrategyCache[lHost]?.let { return it }
        
        val currentGlobal = strategy.value
        if (currentGlobal == BypassStrategy.DIRECT) return BypassStrategy.DIRECT
        
        // If we have failed strategies for this host, avoid them
        if (failed.contains(currentGlobal)) {
            // Try an alternative
            val alternatives = listOf(
                BypassStrategy.SNI_SPLIT, BypassStrategy.FRAGMENT_MULTI, BypassStrategy.FAKE_PACKET, 
                BypassStrategy.TCP_OOB_DESYNC, BypassStrategy.TLS_MIXED_OOB, BypassStrategy.DOUBLE_SPLIT, 
                BypassStrategy.TLS_HOLE_PUNCH, BypassStrategy.TCP_OOB_SPLIT, BypassStrategy.TLS_GHOST_HELLO, 
                BypassStrategy.TLS_FRAG_RANDOM, BypassStrategy.TLS_REC_SPLIT, BypassStrategy.HTTP_LINE_FOLD,
                BypassStrategy.TLS_EXT_SHUFFLE, BypassStrategy.QUIC_VERSION_NEG_FAKE, BypassStrategy.HTTP_HOST_SKEW,
                BypassStrategy.TLS_ALPN_MANGLE, BypassStrategy.HTTP_VERB_CASE, BypassStrategy.TCP_MSS_CLAMP,
                BypassStrategy.TLS_EXT_JUNK, BypassStrategy.HTTP_TE_CHUNKY, BypassStrategy.TCP_URG_SKEW,
                BypassStrategy.TLS_EXT_SKEW, BypassStrategy.HTTP_AUTH_FAKE, BypassStrategy.TCP_FAST_RETRANSMIT_SIM,
                BypassStrategy.QUIC_INITIAL_FRAG, BypassStrategy.TLS_SNI_APPEND_JUNK, BypassStrategy.TCP_SACK_PANIC,
                BypassStrategy.TLS_REC_MANGLE, BypassStrategy.HTTP_PIPE_SIM, BypassStrategy.TCP_REORDER_SIM,
                BypassStrategy.TLS_CLIENT_HELLO_RETRY_SIM, BypassStrategy.HTTP_COOKIE_SKEW,
                BypassStrategy.TCP_FAST_OPEN_FAKE, BypassStrategy.TLS_PADDING_RAND, BypassStrategy.HTTP_HOST_SPACE,
                BypassStrategy.TLS_MULTI_HELLO, BypassStrategy.HTTP_CHUNKED_MANGLE, BypassStrategy.TCP_SYN_FLOOD_FAKE,
                BypassStrategy.TLS_REHANDSHAKE_FAKE, BypassStrategy.HTTP_RANGE_SKEW, BypassStrategy.TCP_RST_FAKE,
                BypassStrategy.QUIC_RANDOM_CID, BypassStrategy.TLS_SNI_SKEW, BypassStrategy.HTTP_VERSION_SKEW,
                BypassStrategy.TCP_TIMESTAMP_MANGLE, BypassStrategy.UDP_NOISE, BypassStrategy.TLS_CIPHER_SHUFFLE,
                BypassStrategy.HTTP_USER_AGENT_SKEW, BypassStrategy.TCP_URGENT_RANDOM
            )
            val available = alternatives.filter { !failed.contains(it) }
            if (available.isNotEmpty()) {
                // Pick best one from global scores
                val picked = available.map { it to (globalStrategyScores[it] ?: 100) }
                                     .sortedByDescending { it.second }
                                     .take(3)
                                     .random().first
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
        ProxyStats.recordResult(false)
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

    private val globalFailedStrategies = ConcurrentHashMap<BypassStrategy, Int>()

    fun recordStrategyResult(host: String, strategy: BypassStrategy, success: Boolean) {
        ProxyStats.recordResult(success)
        lastResults.add(success)
        if (lastResults.size > MAX_HISTORY) lastResults.poll()
        
        if (!success) {
            val gFails = globalFailedStrategies.getOrDefault(strategy, 0) + 1
            globalFailedStrategies[strategy] = gFails
            if (gFails % 20 == 0) {
                globalStrategyScores[strategy] = (globalStrategyScores[strategy] ?: 500).minus(50).coerceAtLeast(10)
            }
        } else {
            // Reward success slightly
            globalStrategyScores[strategy] = (globalStrategyScores[strategy] ?: 500).plus(2).coerceAtMost(1000)
        }

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
        BypassStrategy.TCP_ZERO_WINDOW to 410, BypassStrategy.TLS_FRAG_OOB to 580,
        BypassStrategy.TLS_SPLIT_PAD to 480, BypassStrategy.HTTP_SMUGGLE to 450,
        BypassStrategy.HTTP_OBSCURE to 430, BypassStrategy.DOUBLE_SPLIT to 470,
        BypassStrategy.TLS_MIXED_OOB to 510, BypassStrategy.TLS_HOLE_PUNCH to 530,
        BypassStrategy.TCP_OOB_SPLIT to 540, BypassStrategy.TLS_GHOST_HELLO to 560,
        BypassStrategy.TLS_FRAG_RANDOM to 590, BypassStrategy.TLS_REC_SPLIT to 610,
        BypassStrategy.HTTP_LINE_FOLD to 620, BypassStrategy.QUIC_PAD to 640,
        BypassStrategy.TLS_MULTI_FRAG to 660, BypassStrategy.TCP_SYN_COOKIE_FAKE to 680,
        BypassStrategy.TLS_SESSION_RESUME_FAKE to 700, 
        BypassStrategy.TLS_EXT_SHUFFLE to 720,
        BypassStrategy.QUIC_VERSION_NEG_FAKE to 740,
        BypassStrategy.HTTP_HOST_SKEW to 760,
        BypassStrategy.TLS_ALPN_MANGLE to 780,
        BypassStrategy.HTTP_VERB_CASE to 800,
        BypassStrategy.TCP_MSS_CLAMP to 820,
        BypassStrategy.TLS_EXT_JUNK to 840,
        BypassStrategy.HTTP_TE_CHUNKY to 860,
        BypassStrategy.TCP_URG_SKEW to 880,
        BypassStrategy.TLS_EXT_SKEW to 900,
        BypassStrategy.HTTP_AUTH_FAKE to 920,
        BypassStrategy.TCP_FAST_RETRANSMIT_SIM to 940,
        BypassStrategy.QUIC_INITIAL_FRAG to 950,
        BypassStrategy.TLS_SNI_APPEND_JUNK to 960,
        BypassStrategy.TCP_SACK_PANIC to 970,
        BypassStrategy.TLS_REC_MANGLE to 980,
        BypassStrategy.HTTP_PIPE_SIM to 990,
        BypassStrategy.TCP_REORDER_SIM to 1000,
        BypassStrategy.TCP_FAST_OPEN_FAKE to 1010,
        BypassStrategy.TLS_PADDING_RAND to 1020,
        BypassStrategy.HTTP_HOST_SPACE to 1030,
        BypassStrategy.TLS_MULTI_HELLO to 1040,
        BypassStrategy.HTTP_CHUNKED_MANGLE to 1050,
        BypassStrategy.TCP_SYN_FLOOD_FAKE to 1060,
        BypassStrategy.TLS_REHANDSHAKE_FAKE to 1070,
        BypassStrategy.HTTP_RANGE_SKEW to 1080,
        BypassStrategy.TCP_RST_FAKE to 1090,
        BypassStrategy.QUIC_RANDOM_CID to 1100,
        BypassStrategy.TLS_SNI_SKEW to 1110,
        BypassStrategy.HTTP_VERSION_SKEW to 1120,
        BypassStrategy.TCP_TIMESTAMP_MANGLE to 1130,
        BypassStrategy.UDP_NOISE to 1140,
        BypassStrategy.TLS_CIPHER_SHUFFLE to 1150,
        BypassStrategy.HTTP_USER_AGENT_SKEW to 1160,
        BypassStrategy.TCP_URGENT_RANDOM to 1170,
        BypassStrategy.DIRECT to 1
    )

    private val globalStrategyScores = ConcurrentHashMap<BypassStrategy, Int>().apply { putAll(defaultScores) }

    fun getDnaForHost(host: String): HostDna = hostDnas.getOrPut(host) { HostDna(frag1, frag2, delay1) }

    fun mutateDnaForHost(host: String) {
        val dna = getDnaForHost(host)
        // Evolutionary mutation: randomly adjust parameters to find a working window
        val intensity = ProxyStats.censorshipIntensity.value
        if (intensity > 90) {
            // Aggressive jump mutation for severe censorship
            dna.frag1 = java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 4)
            dna.delay1 = java.util.concurrent.ThreadLocalRandom.current().nextLong(80, 301)
            dna.strategy = null
            ProxyStats.logRecovery("DNA: AGGRESSIVE mutation for $host due to extreme censorship")
        } else {
            when (java.util.concurrent.ThreadLocalRandom.current().nextInt(4)) {
                0 -> dna.frag1 = (dna.frag1 + if (java.util.concurrent.ThreadLocalRandom.current().nextBoolean()) 1 else -1).coerceIn(1, 20)
                1 -> dna.frag2 = (dna.frag2 + if (java.util.concurrent.ThreadLocalRandom.current().nextBoolean()) 1 else -1).coerceIn(1, 25)
                2 -> dna.delay1 = (dna.delay1 + if (java.util.concurrent.ThreadLocalRandom.current().nextBoolean()) 10 else -10).coerceIn(5, 500)
                3 -> {
                    dna.frag1 = java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 8)
                    dna.delay1 = java.util.concurrent.ThreadLocalRandom.current().nextLong(20, 151)
                }
            }
            ProxyStats.logRecovery("DNA: Incremental mutation for $host (Frag: ${dna.frag1}, Delay: ${dna.delay1})")
        }
    }

    fun mutateDnaForAllHosts() {
        hostDnas.keys.forEach { mutateDnaForHost(it) }
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

    fun autoCleanup() {
        // Clear caches if they grow too large (> 1000 hosts)
        if (hostStrategyCache.size > 1000) {
            ProxyStats.logRecovery("CORE: Auto-cleanup triggered (Cache size: ${hostStrategyCache.size})")
            resetCaches()
        }
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
        ProxyStats.recordResult(true)
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
        globalStrategyScores[strategy] = (globalStrategyScores[strategy] ?: 100) + 2
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
        globalStrategyScores[strategy] = ((globalStrategyScores[strategy] ?: 100) - (penalty / 2)).coerceAtLeast(10)
        
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
            else listOf(BypassStrategy.TCP_OOB_DESYNC, BypassStrategy.SNI_TRIPLE, BypassStrategy.TLS_DIRTY, BypassStrategy.TLS_MIXED_OOB, BypassStrategy.TLS_FRAG_RANDOM, BypassStrategy.TLS_GHOST_HELLO, BypassStrategy.TLS_REC_SPLIT, BypassStrategy.HTTP_LINE_FOLD)
            
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

        if (successRate < 50 && !isPanicMode) {
            ProxyStats.logRecovery("CORE: CRITICAL FAILURE RATE. Engaging Automatic Panic Mode.")
            panicOptimize()
        } else if (successRate > 85 && isPanicMode) {
            exitPanicMode()
        } else if (successRate < 70) {
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
            BypassStrategy.TCP_OOB_DESYNC, BypassStrategy.OOB_DESYNC -> {
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
                // We cannot modify TLS Random or Session ID without breaking the cryptographic transcript.
                // Instead, we fragment the ClientHello and insert OOB desync data.
                val split = (len / 3).coerceAtLeast(1)
                out.write(data, 0, split)
                out.flush()
                delay(config.delay1)
                try {
                    // Inject OOB byte to throw off DPI state machine
                    socket.sendUrgentData(java.util.concurrent.ThreadLocalRandom.current().nextInt(256))
                } catch (e: Exception) {}
                val secondSplit = (len * 2 / 3).coerceAtLeast(split + 1).coerceAtMost(len - 1)
                out.write(data, split, secondSplit - split)
                out.flush()
                delay(config.delay2)
                out.write(data, secondSplit, len - secondSplit)
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
            BypassStrategy.SLOW_SEND -> {
                var offset = 0
                while (offset < len) {
                    val chunkSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 4).coerceAtMost(len - offset)
                    out.write(data, offset, chunkSize)
                    out.flush()
                    offset += chunkSize
                    delay(java.util.concurrent.ThreadLocalRandom.current().nextLong(50, 100))
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
            BypassStrategy.PACKET_PADDING -> {
                // Prepend or append data with OOB or fake packet depending on TLS/HTTP
                try {
                    socket.sendUrgentData(0)
                    delay(config.delay1)
                } catch (e: Exception) {}
                out.write(data, 0, len)
            }
            BypassStrategy.TCP_KEEPALIVE -> {
                try {
                    socket.keepAlive = true
                    // Send OOB byte instead of junk application data to trigger window update without breaking TLS/HTTP
                    socket.sendUrgentData(java.util.concurrent.ThreadLocalRandom.current().nextInt(256))
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
            BypassStrategy.HTTP_SMUGGLE -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val str = String(data, 0, len)
                    val mangled = str.replace("\r\n", "\r\n ")
                                     .replace("HTTP/1.1", "HTTP/1.1\r\nTransfer-Encoding: chunked")
                    val mBytes = mangled.toByteArray()
                    out.write(mBytes, 0, mBytes.size)
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.TLS_SPLIT_PAD -> {
                val split = (len / 3).coerceAtLeast(1)
                out.write(data, 0, split)
                out.flush()
                delay(config.delay1)
                
                TtlHelper.setTtl(socket, config.fakeTtl)
                val padding = ByteArray(java.util.concurrent.ThreadLocalRandom.current().nextInt(16, 65)) { 0 }
                out.write(padding)
                out.flush()
                delay(config.delay1)
                TtlHelper.setTtl(socket, 64)
                
                out.write(data, split, len - split)
            }
            BypassStrategy.TLS_FRAG_OOB -> {
                val split = (len / 2).coerceAtLeast(1)
                out.write(data, 0, split)
                out.flush()
                delay(config.delay1)
                
                try {
                    // Send out-of-band urgent data to desynchronize DPI state machine
                    socket.sendUrgentData(java.util.concurrent.ThreadLocalRandom.current().nextInt(256))
                } catch (e: Exception) { android.util.Log.v("PinkProxy", "OOB failed: ${e.message}") }
                
                delay(config.delay2)
                out.write(data, split, len - split)
            }
            BypassStrategy.HTTP_OBSCURE -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val str = String(data, 0, len)
                    val mangled = str.replace("Host:", "Host:  ")
                                     .replace("User-Agent:", "User-Agent:  ")
                                     .replace("Accept:", "Accept:  ")
                                     .replace("Connection:", "Connection:  ")
                    val headersTail = "\r\nSome-Fake-Header: " + java.util.UUID.randomUUID().toString() + "\r\n\r\n"
                    val finalStr = mangled.replace("\r\n\r\n", headersTail)
                    val mBytes = finalStr.toByteArray()
                    out.write(mBytes, 0, mBytes.size)
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.DOUBLE_SPLIT -> {
                val p1 = (len / 3).coerceAtLeast(1)
                val p2 = (len * 2 / 3).coerceAtLeast(p1 + 1).coerceAtMost(len - 1)
                
                out.write(data, 0, p1)
                out.flush()
                delay(config.delay1)
                
                out.write(data, p1, p2 - p1)
                out.flush()
                delay(config.delay2)
                
                out.write(data, p2, len - p2)
            }
            BypassStrategy.TLS_MIXED_OOB -> {
                val p1 = (len / 4).coerceAtLeast(1)
                val p2 = (len / 2).coerceAtLeast(p1 + 1).coerceAtMost(len - 1)
                out.write(data, 0, p1)
                out.flush()
                delay(config.delay1)
                try {
                    socket.sendUrgentData(255)
                } catch (e: Exception) {}
                out.write(data, p1, p2 - p1)
                out.flush()
                delay(config.delay2)
                TtlHelper.setTtl(socket, config.fakeTtl)
                out.write(ByteArray(java.util.concurrent.ThreadLocalRandom.current().nextInt(10, 40)) { 0 })
                out.flush()
                TtlHelper.setTtl(socket, 64)
                out.write(data, p2, len - p2)
            }
            BypassStrategy.TLS_REC_SPLIT -> {
                // Split TLS record into 5-byte header and fragments of payload
                if (len > 5 && data[0] == 0x16.toByte() && data[1] == 0x03.toByte()) {
                    out.write(data, 0, 5) // TLS Header
                    out.flush()
                    delay(config.delay1)
                    
                    var offset = 5
                    while (offset < len) {
                        val remaining = len - offset
                        val chunk = java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 32).coerceAtMost(remaining)
                        out.write(data, offset, chunk)
                        out.flush()
                        offset += chunk
                        if (offset < len) delay(config.delay2 / 5)
                    }
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.HTTP_LINE_FOLD -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val str = String(data, 0, len, java.nio.charset.StandardCharsets.ISO_8859_1)
                    // Insert space after \r\n to fold headers as per RFC 7230 (obsolete but works for DPI)
                    val folded = str.replace("\r\n", "\r\n ")
                    val fBytes = folded.toByteArray(java.nio.charset.StandardCharsets.ISO_8859_1)
                    out.write(fBytes)
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.TLS_FRAG_RANDOM -> {
                var offset = 0
                while (offset < len) {
                    val chunk = java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 4).coerceAtMost(len - offset)
                    out.write(data, offset, chunk)
                    out.flush()
                    delay(config.delay1)
                    offset += chunk
                    
                    // After the first 20 bytes (covering TLS header and early SNI), send the rest
                    if (offset >= 20 && offset < len) {
                        delay(config.delay2)
                        out.write(data, offset, len - offset)
                        out.flush()
                        break
                    }
                }
            }
            BypassStrategy.TLS_GHOST_HELLO -> {
                val fakeHost = listOf("bing.com", "apple.com", "microsoft.com", "cloudflare.com").random()
                val fakeHello = FakePacketHelper.buildFakeClientHello(fakeHost, java.util.concurrent.ThreadLocalRandom.current().nextInt(40, 90))
                TtlHelper.setTtl(socket, config.fakeTtl)
                out.write(fakeHello)
                out.flush()
                delay(config.delay1)
                TtlHelper.setTtl(socket, 64)
                
                val p1 = (len / 2).coerceAtLeast(1)
                out.write(data, 0, p1)
                out.flush()
                delay(config.delay2)
                out.write(data, p1, len - p1)
            }
            BypassStrategy.TLS_HOLE_PUNCH -> {
                val p1 = (len / 5).coerceAtLeast(1)
                val p2 = (len * 3 / 5).coerceAtLeast(p1 + 1).coerceAtMost(len - 1)
                out.write(data, 0, p1)
                out.flush()
                delay(config.delay1)
                TtlHelper.setTtl(socket, config.fakeTtl)
                out.write(ByteArray(java.util.concurrent.ThreadLocalRandom.current().nextInt(32, 128)) { java.util.concurrent.ThreadLocalRandom.current().nextInt(256).toByte() })
                out.flush()
                TtlHelper.setTtl(socket, 64)
                out.write(data, p1, p2 - p1)
                out.flush()
                delay(config.delay2)
                out.write(data, p2, len - p2)
            }
            BypassStrategy.TCP_OOB_SPLIT -> {
                val p1 = (len / 2).coerceAtLeast(1)
                out.write(data, 0, p1)
                out.flush()
                delay(config.delay1)
                try {
                    socket.sendUrgentData(java.util.concurrent.ThreadLocalRandom.current().nextInt(256))
                    delay(config.delay2)
                } catch (e: Exception) {}
                out.write(data, p1, len - p1)
            }
            BypassStrategy.QUIC_PAD -> {
                // For UDP/QUIC (if called from elsewhere) or as a generic padding for TCP
                out.write(data, 0, len)
                val paddingSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(64, 256)
                out.write(ByteArray(paddingSize) { 0 })
                out.flush()
            }
            BypassStrategy.TLS_MULTI_FRAG -> {
                // Fragment almost everything into tiny pieces
                var offset = 0
                while (offset < len) {
                    val remaining = len - offset
                    val chunkSize = if (offset < 40) {
                        java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 4)
                    } else {
                        java.util.concurrent.ThreadLocalRandom.current().nextInt(32, 128)
                    }.coerceAtMost(remaining)
                    
                    out.write(data, offset, chunkSize)
                    out.flush()
                    offset += chunkSize
                    if (offset < len) delay(config.delay1 / 10)
                }
            }
            BypassStrategy.TCP_SYN_COOKIE_FAKE -> {
                // We can't really change SYN at this layer, so we simulate a "resync" with urgent data
                try {
                    socket.sendUrgentData(0xAA)
                    delay(10)
                    socket.sendUrgentData(0x55)
                    delay(config.delay1)
                } catch (e: Exception) {}
                out.write(data, 0, len)
            }
            BypassStrategy.TLS_SESSION_RESUME_FAKE -> {
                // Add a fake TLS Session ID if it looks like a ClientHello without one
                if (len > 43 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                    // This is a very simplified "injection" that might break the packet if not careful
                    // Better approach: just use it as a trigger for extreme delay
                    out.write(data, 0, 43)
                    out.flush()
                    delay(config.delay1 * 2)
                    out.write(data, 43, len - 43)
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.TLS_EXT_SHUFFLE -> {
                // Skew extension processing by splitting into many tiny TLS fragments if it's a ClientHello
                if (len > 5 && data[0] == 0x16.toByte() && data[1] == 0x03.toByte()) {
                    var offset = 0
                    while (offset < len) {
                        val remaining = len - offset
                        val chunkSize = if (offset < 43) 43 - offset else java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 3)
                        val actualSize = chunkSize.coerceAtMost(remaining)
                        out.write(data, offset, actualSize)
                        out.flush()
                        offset += actualSize
                        if (offset < len) delay(config.delay1 / 5)
                    }
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.QUIC_VERSION_NEG_FAKE -> {
                // Send a fake QUIC Version Negotiation packet (UDP-like) as junk before TCP handshake payloads
                val quicJunk = ByteArray(java.util.concurrent.ThreadLocalRandom.current().nextInt(100, 200))
                quicJunk[0] = 0x80.toByte() // Long header
                // Add some random version numbers
                TtlHelper.setTtl(socket, config.fakeTtl)
                out.write(quicJunk); out.flush(); delay(15)
                TtlHelper.setTtl(socket, 64)
                out.write(data, 0, len)
            }
            BypassStrategy.HTTP_HOST_SKEW -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val str = String(data, 0, len, java.nio.charset.StandardCharsets.ISO_8859_1)
                    // Obfuscate Host header with mixed case and tab injections
                    val skewed = str.replace("Host: ", "hOsT:\t")
                    val sBytes = skewed.toByteArray(java.nio.charset.StandardCharsets.ISO_8859_1)
                    out.write(sBytes)
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.TLS_ALPN_MANGLE -> {
                // Find ALPN extension in ClientHello and swap characters or add junk
                if (len > 100 && data[0] == 0x16.toByte() && data[1] == 0x03.toByte()) {
                    var alpnIdx = -1
                    for (i in 0 until len - 1) {
                        if (data[i] == 'h'.code.toByte() && data[i+1] == '2'.code.toByte()) {
                            alpnIdx = i; break
                        }
                    }
                    if (alpnIdx != -1) {
                        val newData = data.copyOf()
                        newData[alpnIdx] = 'H'.code.toByte()
                        out.write(newData, 0, len)
                    } else {
                        out.write(data, 0, len)
                    }
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.HTTP_VERB_CASE -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val str = String(data, 0, len, java.nio.charset.StandardCharsets.ISO_8859_1)
                    val skewed = str.replace("GET ", "gEt ").replace("POST ", "pOsT ")
                    val sBytes = skewed.toByteArray(java.nio.charset.StandardCharsets.ISO_8859_1)
                    out.write(sBytes)
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.TCP_MSS_CLAMP -> {
                // We can't change MSS here easily, so we fragment into exactly 512 byte chunks
                var offset = 0
                while (offset < len) {
                    val remaining = len - offset
                    val chunk = 512.coerceAtMost(remaining)
                    out.write(data, offset, chunk)
                    out.flush()
                    offset += chunk
                    if (offset < len) delay(config.delay1)
                }
            }
            BypassStrategy.TLS_EXT_JUNK -> {
                if (len > 100 && data[0] == 0x16.toByte() && data[1] == 0x03.toByte()) {
                    var offset = 0
                    while (offset < len) {
                        val remaining = len - offset
                        val chunk = if (offset < 50) 1 else java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 32)
                        val actual = chunk.coerceAtMost(remaining)
                        out.write(data, offset, actual)
                        out.flush()
                        offset += actual
                        if (offset < len) delay(config.delay1 / 2)
                    }
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.HTTP_TE_CHUNKY -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val str = String(data, 0, len, java.nio.charset.StandardCharsets.ISO_8859_1)
                    val chunked = str.replace("HTTP/1.1", "HTTP/1.1\r\nTransfer-Encoding: chunked")
                    out.write(chunked.toByteArray(java.nio.charset.StandardCharsets.ISO_8859_1))
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.TCP_URG_SKEW -> {
                var offset = 0
                while (offset < len) {
                    val chunk = java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 16).coerceAtMost(len - offset)
                    try {
                        socket.sendUrgentData(data[offset].toInt())
                    } catch (e: Exception) {}
                    out.write(data, offset, chunk)
                    out.flush()
                    offset += chunk
                    if (offset < len) delay(config.delay1)
                }
            }
            BypassStrategy.TLS_EXT_SKEW -> {
                if (len > 100 && data[0] == 0x16.toByte() && data[1] == 0x03.toByte()) {
                    // Send first 43 bytes (up to random session ID)
                    out.write(data, 0, 43)
                    out.flush()
                    delay(config.delay1)
                    // Send 1 byte of junk (simulating extension skew)
                    out.write(byteArrayOf(0x00)) 
                    out.flush()
                    delay(config.delay1 / 4)
                    // Send the rest
                    out.write(data, 43, len - 43)
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.HTTP_AUTH_FAKE -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val str = String(data, 0, len, java.nio.charset.StandardCharsets.ISO_8859_1)
                    val fakeHeader = "Authorization: Basic ${java.util.UUID.randomUUID().toString().take(12)}\r\n"
                    val skewed = str.replaceFirst("\r\n", "\r\n$fakeHeader")
                    out.write(skewed.toByteArray(java.nio.charset.StandardCharsets.ISO_8859_1))
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.TCP_FAST_RETRANSMIT_SIM -> {
                val mid = len / 2
                if (mid > 0) {
                    out.write(data, 0, mid)
                    out.flush()
                    delay(5)
                    out.write(data, 0, mid) // Simulating retransmit of first half
                    out.flush()
                    out.write(data, mid, len - mid)
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.QUIC_INITIAL_FRAG -> {
                // QUIC packets are usually large. Fragment them significantly if it looks like QUIC (UDP 443 often)
                if (len > 1200) {
                    var offset = 0
                    while (offset < len) {
                        val chunk = 256.coerceAtMost(len - offset)
                        out.write(data, offset, chunk)
                        out.flush()
                        offset += chunk
                        delay(config.delay1)
                    }
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.TLS_SNI_APPEND_JUNK -> {
                if (len > 100 && data[0] == 0x16.toByte() && data[1] == 0x03.toByte()) {
                    // Find SNI and append some junk bytes to the extension
                    val newData = ByteArray(len + 4)
                    System.arraycopy(data, 0, newData, 0, len)
                    newData[len] = 0x00
                    newData[len+1] = 0x00
                    newData[len+2] = 0x00
                    newData[len+3] = 0x00
                    out.write(newData)
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.TCP_SACK_PANIC -> {
                // Simulating strange TCP behavior by sending data in overlapping chunks
                val mid = len / 2
                if (mid > 0) {
                    out.write(data, 0, mid + 1)
                    out.flush()
                    delay(2)
                    out.write(data, mid, len - mid)
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.TLS_REC_MANGLE -> {
                if (len > 5 && data[0] == 0x16.toByte()) {
                    // Mangle TLS record length field if possible (tricky without parsing)
                    // Simple mangle: send header, then small delay, then body
                    out.write(data, 0, 5)
                    out.flush()
                    delay(config.delay1)
                    out.write(data, 5, len - 5)
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.HTTP_PIPE_SIM -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    // Simulate HTTP pipelining by appending a fake GET request after the real one
                    val str = String(data, 0, len, java.nio.charset.StandardCharsets.ISO_8859_1)
                    val fakeGet = "GET /favicon.ico HTTP/1.1\r\nHost: ${java.util.UUID.randomUUID().toString().take(8)}.com\r\n\r\n"
                    val piped = str + fakeGet
                    out.write(piped.toByteArray(java.nio.charset.StandardCharsets.ISO_8859_1))
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.TCP_REORDER_SIM -> {
                if (len > 200) {
                    val mid = len / 2
                    out.write(data, mid, len - mid)
                    out.flush()
                    delay(config.delay1 * 2)
                    out.write(data, 0, mid)
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.TLS_CLIENT_HELLO_RETRY_SIM -> {
                if (len > 100 && data[0] == 0x16.toByte()) {
                    // Send a fake ClientHello that looks like it expects a HelloRetryRequest
                    val fakeHello = FakePacketHelper.buildFakeClientHello(host, 64)
                    TtlHelper.setTtl(socket, config.fakeTtl)
                    out.write(fakeHello)
                    out.flush()
                    delay(config.delay1)
                    TtlHelper.setTtl(socket, 64)
                    // Now send the real one
                    out.write(data, 0, len)
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.HTTP_COOKIE_SKEW -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val str = String(data, 0, len, java.nio.charset.StandardCharsets.ISO_8859_1)
                    val skewed = str.replace("Cookie: ", "cOoKiE: ")
                                     .replace("cookie: ", "CoOkIe: ")
                    out.write(skewed.toByteArray(java.nio.charset.StandardCharsets.ISO_8859_1))
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.TCP_ACK_DELAY_SIM -> {
                // Simulate ACK delay by splitting payload and adding a small wait
                val p1 = (len / 2).coerceAtLeast(1)
                out.write(data, 0, p1)
                out.flush()
                delay(config.delay1.coerceAtMost(50L))
                out.write(data, p1, len - p1)
            }
            BypassStrategy.TCP_FAST_OPEN_FAKE -> {
                if (len > 100 && data[0] == 0x16.toByte()) {
                    // Send first chunk, wait, then second chunk to simulate TFO data flow
                    val p1 = 64.coerceAtMost(len)
                    out.write(data, 0, p1)
                    out.flush()
                    delay(config.delay1)
                    out.write(data, p1, len - p1)
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.TLS_PADDING_RAND -> {
                if (len > 5 && data[0] == 0x16.toByte()) {
                    // Append random padding to the TLS record if it looks like a handshake
                    val paddingSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(16, 129)
                    val newData = ByteArray(len + paddingSize)
                    System.arraycopy(data, 0, newData, 0, len)
                    java.util.concurrent.ThreadLocalRandom.current().nextBytes(newData.copyOfRange(len, len + paddingSize))
                    out.write(newData)
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.HTTP_HOST_SPACE -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val str = String(data, 0, len, java.nio.charset.StandardCharsets.ISO_8859_1)
                    val skewed = str.replace("Host: ", "Host:  ") // Double space after Host:
                    out.write(skewed.toByteArray(java.nio.charset.StandardCharsets.ISO_8859_1))
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.TLS_MULTI_HELLO -> {
                if (len > 100 && data[0] == 0x16.toByte()) {
                    // Send fragmented ClientHello header, then junk, then real body
                    out.write(data, 0, 5)
                    out.flush()
                    delay(config.delay1)
                    val junk = ByteArray(32)
                    java.util.concurrent.ThreadLocalRandom.current().nextBytes(junk)
                    out.write(junk)
                    out.flush()
                    delay(config.delay1)
                    out.write(data, 5, len - 5)
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.HTTP_CHUNKED_MANGLE -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val str = String(data, 0, len, java.nio.charset.StandardCharsets.ISO_8859_1)
                    val skewed = str.replace("Transfer-Encoding: chunked", "Transfer-Encoding:  chunked")
                    out.write(skewed.toByteArray(java.nio.charset.StandardCharsets.ISO_8859_1))
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.TCP_SYN_FLOOD_FAKE -> {
                // Not a real SYN flood, but sending very small data chunks to trigger DPI analysis overhead
                val chunk = 1.coerceAtMost(len)
                for (i in 0 until len step chunk) {
                    val size = chunk.coerceAtMost(len - i)
                    out.write(data, i, size)
                    out.flush()
                    delay(1)
                }
            }
            BypassStrategy.TLS_REHANDSHAKE_FAKE -> {
                if (len > 100 && data[0] == 0x16.toByte()) {
                    out.write(data, 0, len)
                    out.flush()
                    delay(config.delay1)
                    val helloRequest = byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00)
                    out.write(helloRequest)
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.HTTP_RANGE_SKEW -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val str = String(data, 0, len, java.nio.charset.StandardCharsets.ISO_8859_1)
                    val skewed = if (!str.contains("Range:")) {
                        str.replace("\r\n\r\n", "\r\nRange: bytes=0-\r\n\r\n")
                    } else str
                    out.write(skewed.toByteArray(java.nio.charset.StandardCharsets.ISO_8859_1))
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.TCP_RST_FAKE -> {
                if (len > 0) {
                    try { socket.sendUrgentData(0xFF) } catch (e: Exception) {}
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.QUIC_RANDOM_CID -> {
                out.write(data, 0, len)
            }
            BypassStrategy.TLS_SNI_SKEW -> {
                if (len > 100 && data[0] == 0x16.toByte()) {
                    val str = String(data, 0, len, java.nio.charset.StandardCharsets.ISO_8859_1)
                    // Simple SNI skew: append a dot to the host if it's found in the binary (very crude for now)
                    // Real implementation would parse the ClientHello properly
                    val skewed = str.replace(host, "$host.")
                    out.write(skewed.toByteArray(java.nio.charset.StandardCharsets.ISO_8859_1))
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.HTTP_VERSION_SKEW -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val str = String(data, 0, len, java.nio.charset.StandardCharsets.ISO_8859_1)
                    val skewed = str.replace("HTTP/1.1", "HTTP/1.0")
                    out.write(skewed.toByteArray(java.nio.charset.StandardCharsets.ISO_8859_1))
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.TCP_TIMESTAMP_MANGLE -> {
                // We can't easily mangle TCP timestamps from user-space, so we simulate by varying delay
                delay(java.util.concurrent.ThreadLocalRandom.current().nextLong(1, 10))
                out.write(data, 0, len)
            }
            BypassStrategy.TLS_CIPHER_SHUFFLE -> {
                if (len > 100 && data[0] == 0x16.toByte()) {
                    // This is a very simplified simulation of cipher shuffling.
                    // Real one would require full TLS parsing.
                    val shuffled = data.copyOf()
                    if (len > 50) {
                         // Swap some bytes in the extensions/ciphers area (dangerous without parsing)
                         // For now, just add a small delay and a padding
                         out.write(data, 0, 5)
                         out.flush()
                         delay(1)
                         out.write(data, 5, len - 5)
                    } else {
                        out.write(data, 0, len)
                    }
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.HTTP_USER_AGENT_SKEW -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val str = String(data, 0, len, java.nio.charset.StandardCharsets.ISO_8859_1)
                    val skewed = str.replace("User-Agent: ", "User-Agent:  ") // Extra space
                                    .replace("User-Agent:", "user-agent:")   // Case change
                    out.write(skewed.toByteArray(java.nio.charset.StandardCharsets.ISO_8859_1))
                } else {
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.TCP_URGENT_RANDOM -> {
                if (len > 0) {
                    if (java.util.concurrent.ThreadLocalRandom.current().nextBoolean()) {
                        try { socket.sendUrgentData(java.util.concurrent.ThreadLocalRandom.current().nextInt(0, 256)) } catch (e: Exception) {}
                    }
                    out.write(data, 0, len)
                }
            }
            BypassStrategy.UDP_NOISE -> {
                // UDP strategy applied to TCP: just pass through
                out.write(data, 0, len)
            }
            BypassStrategy.DIRECT -> {
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
            // Restore last good strategy for this network
            networkStrategyMemory[netType]?.let { remembered ->
                if (_currentStrategy.value != remembered) {
                    ProxyStats.logRecovery("NETWORK: Restoring last known good strategy for ${netType.name}: ${remembered.name}")
                    _currentStrategy.value = remembered
                }
            }

            // Reset adaptive metrics for the new network
            hostConsecutiveSuccesses.clear()
            hostConsecutiveFailures.clear()
            lastResults.clear()
            resetCaches() // Full reset on network switch to re-explore best strategies
            ProxyStats.logRecovery("NETWORK: Switched to ${netType.name}. All caches and metrics reset.")
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
            putBoolean("isDiagnosticMode", isDiagnosticMode)
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
        isDiagnosticMode = prefs.getBoolean("isDiagnosticMode", isDiagnosticMode)
    }
    
    fun clearScores(context: android.content.Context? = null) {
        resetToDefaults()
        if (context != null) {
            val prefs = context.getSharedPreferences("pink_proxy_scores", android.content.Context.MODE_PRIVATE)
            prefs.edit { clear() }
        }
    }

    fun getStrategyScore(strategy: BypassStrategy): Int {
        val scores = getNetworkScoresMap()
        return scores[strategy] ?: 100
    }
    
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
                    // Cleanup expired connections in the pool
                    val iterator = connectionPool.entries.iterator()
                    while (iterator.hasNext()) {
                        val entry = iterator.next()
                        val queue = entry.value
                        val toRemove = mutableListOf<PooledConnection>()
                        for (pc in queue) {
                            if (!pc.isAlive()) {
                                toRemove.add(pc)
                                try { pc.socket.close() } catch (e: Exception) {}
                            }
                        }
                        queue.removeAll(toRemove)
                        if (queue.isEmpty()) {
                            iterator.remove()
                        }
                    }

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
                                vpnService.protect(sock)
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

    private fun startGlobalProber() {
        serverScope.launch {
            while (isActive) {
                delay(180000) // Proactively probe every 3 minutes
                if (BypassConfig.activeVpnService != null) {
                    // Pick a candidate that is NOT the current global best and has potential
                    val currentBest = BypassConfig.getGlobalBestStrategy()
                    val candidates = BypassStrategy.entries.filter { it != BypassStrategy.DIRECT && it != currentBest }
                    
                    // Prioritize strategies that we haven't tested recently or have low but non-zero scores
                    val candidate = candidates.minByOrNull { BypassConfig.getStrategyScore(it) } ?: candidates.random()
                    
                    val testHost = "1.1.1.1"
                    try {
                        val socket = java.net.Socket()
                        BypassConfig.activeVpnService?.protect(socket)
                        socket.connect(java.net.InetSocketAddress(testHost, 443), 5000)
                        socket.close()
                        BypassConfig.recordStrategyResult(testHost, candidate, true)
                        ProxyStats.logRecovery("PROBER: Proactive SUCCESS for ${candidate.name} (Score: ${BypassConfig.getStrategyScore(candidate)})")
                    } catch (e: Exception) {
                        BypassConfig.recordStrategyResult(testHost, candidate, false)
                        ProxyStats.logRecovery("PROBER: Proactive FAILURE for ${candidate.name}")
                    }
                }
            }
        }
    }

    init {
        startPreWarmer()
        startGlobalProber()
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
                delay(java.util.concurrent.ThreadLocalRandom.current().nextLong(60000, 300000)) // Every 1-5 minutes
                if (BypassConfig.activeVpnService != null) {
                    try {
                        val camHosts = listOf("google.com", "bing.com", "cloudflare.com", "apple.com", "microsoft.com", "amazon.com", "wikipedia.org")
                        val host = camHosts.random()
                        BypassConfig.shadowProbe(host, BypassStrategy.DIRECT) // Send a direct ClientHello or HTTP to fake innocent traffic
                        ProxyStats.logRecovery("CORE: Camouflage HTTP/TLS burst for $host executed.")
                    } catch (e: Exception) { }
                }
            }
        }

        // Stability Watchdog
        serverScope.launch {
            var lastRtt = 0L
            while (isActive) {
                delay(90000) 
                val stability = ProxyStats.stabilityScore.value
                val currentRtt = BypassConfig.getCurrentRttMs()
                
                // Detection of RTT spike (> 2x previous or > 500ms)
                if (currentRtt > 500 && currentRtt > lastRtt * 2 && lastRtt > 0) {
                    ProxyStats.logRecovery("WATCHDOG: RTT SPIKE DETECTED ($currentRtt ms). Throttling MTU to stabilize.")
                    BypassConfig.offsetMtu(-100)
                }
                lastRtt = currentRtt

                if (stability < 30 && stability > 0) {
                    ProxyStats.logRecovery("WATCHDOG: CRITICAL STABILITY ($stability%). EMERGENCY RESET.")
                    BypassConfig.enterPanicMode()
                    BypassConfig.mutateDnaForAllHosts()
                    serverScope.launch { BypassConfig.runStrategyBenchmark() }
                } else if (stability < 60 && stability > 0) {
                    ProxyStats.logRecovery("WATCHDOG: STABILITY LOW ($stability%). Triggering emergency optimization.")
                    BypassConfig.optimizeNetworkParameters()
                    serverScope.launch { BypassConfig.runStrategyBenchmark() }
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
            } catch (e: java.net.SocketException) {
                // Expected when stopping
            } catch (e: Exception) { Log.e("PinkProxyServer", "TCP Server failed", e) }
        }

        serverScope.launch {
            while (isActive) {
                delay(60000)
                val now = System.currentTimeMillis()
                val iterator = udpSessions.entries.iterator()
                while (iterator.hasNext()) {
                    val entry = iterator.next()
                    if (now - entry.value.lastActivity > 120000) { // 2 mins idle
                        try { entry.value.targetSocket.close() } catch (e: Exception) {}
                        iterator.remove()
                    }
                }
            }
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
            } catch (e: java.net.SocketException) {
                // Expected when stopping
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
            4 -> { // IPv6
                if (len < 22) return
                val addrBytes = data.copyOfRange(4, 20)
                dstHost = java.net.InetAddress.getByAddress(addrBytes).hostAddress ?: ""
                dstPort = ((data[20].toInt() and 0xFF) shl 8) or (data[21].toInt() and 0xFF)
                headerLen = 22
            }
            else -> return // Unknown
        }
        
        val payload = data.copyOfRange(headerLen, len)
        val clientKey = "${packet.address.hostAddress}:${packet.port}"
        var session = udpSessions[clientKey]
        
        if (session == null || session.targetSocket.isClosed) {
            val sock = java.net.DatagramSocket()
            vpnService.protect(sock)
            session = UdpSession(packet.address, packet.port, sock, System.currentTimeMillis())
            udpSessions[clientKey] = session
            
            serverScope.launch(Dispatchers.IO) {
                val buf = ByteArray(16384)
                while (isActive && !sock.isClosed) {
                    try {
                        val rxPacket = java.net.DatagramPacket(buf, buf.size)
                        sock.receive(rxPacket)
                        
                        val replyPort = rxPacket.port
                        val ipBytes = rxPacket.address.address
                        val header = if (ipBytes.size == 4) {
                            byteArrayOf(0, 0, 0, 1, ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3], (replyPort shr 8).toByte(), replyPort.toByte())
                        } else {
                            byteArrayOf(0, 0, 0, 1, 0, 0, 0, 0, (replyPort shr 8).toByte(), replyPort.toByte())
                        }
                        
                        val finalPayload = ByteArray(header.size + rxPacket.length)
                        System.arraycopy(header, 0, finalPayload, 0, header.size)
                        System.arraycopy(rxPacket.data, 0, finalPayload, header.size, rxPacket.length)
                        
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
            val targetAddr = if (RobustResolver.isIpAddress(dstHost)) java.net.InetAddress.getByName(dstHost) else RobustResolver.resolve(dstHost, vpnService).firstOrNull()
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

                val strategy = BypassConfig.getBestStrategyForHost(dstHost)
                val finalPayload = if (strategy == BypassStrategy.UDP_NOISE && payload.size < 1200) {
                    val noiseSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 64)
                    val combined = ByteArray(payload.size + noiseSize)
                    System.arraycopy(payload, 0, combined, 0, payload.size)
                    val noise = ByteArray(noiseSize)
                    java.util.concurrent.ThreadLocalRandom.current().nextBytes(noise)
                    System.arraycopy(noise, 0, combined, payload.size, noiseSize)
                    combined
                } else payload

                val outPacket = java.net.DatagramPacket(finalPayload, finalPayload.size, targetAddr, dstPort)
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
                if (read >= 20) {
                    val addrBytes = reqBuf.copyOfRange(4, 20)
                    host = java.net.InetAddress.getByAddress(addrBytes).hostAddress ?: ""
                }
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
                            val maxRaceIps = if (BypassConfig.isCharging) 4 else 2
                            val ipsToRace = ips.take(maxRaceIps)
                            val raceDelay = if (BypassConfig.isCharging) 150L else 250L
                            
                            for (ip in ipsToRace) {
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
                            val maxRaceIps = if (BypassConfig.isCharging) 4 else 2
                            val ipsToRace = ips.take(maxRaceIps)
                            val raceDelay = if (BypassConfig.isCharging) 150L else 250L
                            
                            for (ip in ipsToRace) {
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
                            val maxRaceIps = if (BypassConfig.isCharging) 4 else 2
                            val ipsToRace = ips.take(maxRaceIps)
                            val raceDelay = if (BypassConfig.isCharging) 150L else 250L
                            
                            for (ip in ipsToRace) {
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
                                delay(raceDelay)
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
    }    private suspend fun proxyStream(input: InputStream, output: OutputStream, onError: () -> Unit, host: String?, isRecv: Boolean, strategy: BypassStrategy?) {
        val bufSize = if (isRecv) 16384 else 8192
        val buf = BypassConfig.TrafficShaper.acquireBuffer(bufSize)
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
                    
                    if (!isRecv && strategy != null && strategy != BypassStrategy.DIRECT && totalProcessedBytes < 16384) {
                        var offset = 0
                        while (offset < r) {
                            val remaining = r - offset
                            val chunkSize = when (strategy) {
                                BypassStrategy.WINDOW_SIZE, BypassStrategy.TCP_WINDOW_CLAMP -> rnd.nextInt(16, 129)
                                BypassStrategy.SLOW_SEND -> rnd.nextInt(64, 512)
                                BypassStrategy.FRAGMENT_MULTI -> rnd.nextInt(32, 513)
                                BypassStrategy.TLS_REC_SPLIT -> rnd.nextInt(5, 64)
                                BypassStrategy.TLS_MULTI_FRAG -> rnd.nextInt(1, 4)
                                BypassStrategy.CHAOS -> if (rnd.nextBoolean()) rnd.nextInt(1, 16) else rnd.nextInt(64, 1024)
                                BypassStrategy.TCP_MSS_CLAMP -> 512
                                BypassStrategy.TCP_URG_SKEW -> rnd.nextInt(1, 16)
                                BypassStrategy.TLS_EXT_SKEW -> if (offset < 64) 1 else rnd.nextInt(64, 512)
                                BypassStrategy.TCP_FAST_RETRANSMIT_SIM -> rnd.nextInt(128, 1024)
                                BypassStrategy.TLS_REC_MANGLE -> if (offset < 5) 5 else rnd.nextInt(64, 512)
                                BypassStrategy.TCP_REORDER_SIM -> rnd.nextInt(128, 512)
                                BypassStrategy.TCP_FAST_OPEN_FAKE -> if (offset < 64) 64 else rnd.nextInt(128, 1024)
                                BypassStrategy.TLS_PADDING_RAND -> rnd.nextInt(256, 1400)
                                BypassStrategy.HTTP_HOST_SPACE -> rnd.nextInt(32, 256)
                                BypassStrategy.TLS_REHANDSHAKE_FAKE -> rnd.nextInt(5, 100)
                                BypassStrategy.HTTP_RANGE_SKEW -> rnd.nextInt(16, 256)
                                BypassStrategy.TCP_RST_FAKE -> rnd.nextInt(1, 100)
                                BypassStrategy.QUIC_RANDOM_CID -> rnd.nextInt(32, 512)
                                BypassStrategy.TLS_SNI_SKEW -> rnd.nextInt(64, 256)
                                BypassStrategy.HTTP_VERSION_SKEW -> rnd.nextInt(16, 512)
                                BypassStrategy.TCP_TIMESTAMP_MANGLE -> rnd.nextInt(128, 1024)
                                BypassStrategy.TLS_CIPHER_SHUFFLE -> rnd.nextInt(32, 256)
                                BypassStrategy.HTTP_USER_AGENT_SKEW -> rnd.nextInt(16, 512)
                                BypassStrategy.TCP_URGENT_RANDOM -> rnd.nextInt(1, 100)
                                BypassStrategy.UDP_NOISE -> if (remaining < 256) remaining else rnd.nextInt(64, remaining.coerceAtMost(1400) + 1)
                                else -> if (remaining < 256) remaining else rnd.nextInt(64, remaining.coerceAtMost(1400) + 1)
                            }.coerceAtMost(remaining)
                            
                            output.write(buf, offset, chunkSize)
                            output.flush()
                            
                            val pace = when (strategy) {
                                BypassStrategy.WINDOW_SIZE -> rnd.nextLong(10, 31)
                                BypassStrategy.SLOW_SEND -> rnd.nextLong(50, 101)
                                BypassStrategy.TLS_REC_SPLIT -> rnd.nextLong(15, 45)
                                BypassStrategy.TLS_MULTI_FRAG -> rnd.nextLong(2, 8)
                                BypassStrategy.CHAOS -> rnd.nextLong(1, 100)
                                BypassStrategy.TCP_URG_SKEW -> rnd.nextLong(10, 50)
                                BypassStrategy.TLS_EXT_SKEW -> rnd.nextLong(20, 100)
                                BypassStrategy.TCP_FAST_RETRANSMIT_SIM -> rnd.nextLong(5, 20)
                                BypassStrategy.TLS_REC_MANGLE -> rnd.nextLong(5, 30)
                                BypassStrategy.TCP_REORDER_SIM -> rnd.nextLong(30, 150)
                                BypassStrategy.TCP_FAST_OPEN_FAKE -> rnd.nextLong(20, 120)
                                BypassStrategy.TLS_PADDING_RAND -> rnd.nextLong(5, 50)
                                BypassStrategy.HTTP_HOST_SPACE -> rnd.nextLong(10, 40)
                                BypassStrategy.TLS_REHANDSHAKE_FAKE -> rnd.nextLong(15, 60)
                                BypassStrategy.HTTP_RANGE_SKEW -> rnd.nextLong(5, 25)
                                BypassStrategy.TCP_RST_FAKE -> rnd.nextLong(20, 100)
                                BypassStrategy.QUIC_RANDOM_CID -> rnd.nextLong(5, 30)
                                BypassStrategy.TLS_SNI_SKEW -> rnd.nextLong(10, 50)
                                BypassStrategy.HTTP_VERSION_SKEW -> rnd.nextLong(5, 40)
                                BypassStrategy.TCP_TIMESTAMP_MANGLE -> rnd.nextLong(2, 20)
                                BypassStrategy.TLS_CIPHER_SHUFFLE -> rnd.nextLong(10, 60)
                                BypassStrategy.HTTP_USER_AGENT_SKEW -> rnd.nextLong(5, 30)
                                BypassStrategy.TCP_URGENT_RANDOM -> rnd.nextLong(10, 100)
                                BypassStrategy.UDP_NOISE -> rnd.nextLong(1, 3)
                                else -> rnd.nextLong(1, 3)
                            }
                            delay(pace)
                            offset += chunkSize
                        }
                        totalProcessedBytes += r
                    } else {
                        output.write(buf, 0, r)
                        output.flush()
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
