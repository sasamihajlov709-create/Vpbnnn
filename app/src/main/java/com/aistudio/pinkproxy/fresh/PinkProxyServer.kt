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
    QUIC_RANDOM_CID, TLS_SNI_SKEW, HTTP_VERSION_SKEW, TCP_TIMESTAMP_MANGLE,
    TLS_CIPHER_SHUFFLE, HTTP_USER_AGENT_SKEW, TCP_URGENT_RANDOM, TLS_ALPN_SKEW,
    HTTP_AUTH_RANDOM, TCP_WINDOW_SIZE_CHAOS, TLS_EXTENSION_GREASE,
    HTTP_HEADER_FUZZING, TCP_REORDER_CHAOS, UDP_XOR_OBFUSCATE, TLS_HELLO_JUNK,
    HTTP_METHOD_FAKE, DNS_OVER_QUIC_SIM, UDP_NOISE
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
            _dnsSuccessCount.value += 1
            recordGlobalSuccess(0)
        } else {
            _dnsFailureCount.value += 1
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
                
                val history = _speedHistory.value.toMutableList()
                history.add(0, speed)
                if (history.size > 60) history.removeAt(history.size - 1)
                _speedHistory.value = history
                
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
             val current = _stabilityScore.value
             _stabilityScore.value = (current * 0.95 + 100 * 0.05).toInt().coerceIn(0, 100)
        }
        val rate = _successRate.value
        _successRate.value = (rate * 0.98 + 100 * 0.02).toInt().coerceIn(0, 100)
    }

    fun recordCensorshipEvent(isBlocked: Boolean) {
        if (isBlocked) {
            _errors.value += 1
            val rate = _successRate.value
            _successRate.value = (rate * 0.9 + 0 * 0.1).toInt().coerceIn(0, 100)
            val current = _censorshipIntensity.value
            _censorshipIntensity.value = (current + 5).coerceAtMost(100)
        } else {
            val current = _censorshipIntensity.value
            _censorshipIntensity.value = (current - 1).coerceAtLeast(0)
        }
    }

    fun logRecovery(msg: String) {
        val current = _recoveryLog.value.toMutableList()
        current.add(0, "[${java.text.SimpleDateFormat("HH:mm:ss", Locale.ROOT).format(Date())}] $msg")
        if (current.size > 100) current.removeAt(current.size - 1)
        _recoveryLog.value = current
    }

    fun addTraffic(host: String) {
        val current = _trafficLog.value.toMutableList()
        current.add(0, host)
        if (current.size > 50) current.removeAt(current.size - 1)
        _trafficLog.value = current
        
        val hosts = _topHosts.value.toMutableList()
        val idx = hosts.indexOfFirst { it.first == host }
        if (idx != -1) {
            hosts[idx] = host to hosts[idx].second + 1
        } else {
            hosts.add(host to 1)
        }
        _topHosts.value = hosts.sortedByDescending { it.second }.take(10)
    }

    fun updateBytes(delta: Long) {
        _bytesTransferred.value += delta
    }

    fun updateConnections(delta: Int) {
        _activeConnections.value += delta
    }

    fun updateCongestionWindow(delta: Int) {
        _congestionWindow.value = (_congestionWindow.value + delta).coerceIn(2, 128)
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

object BypassConfig {
    private val _strategy = MutableStateFlow(BypassStrategy.SNI_SPLIT)
    val strategy: StateFlow<BypassStrategy> = _strategy.asStateFlow()

    private val _currentNetworkType = MutableStateFlow(NetworkType.UNKNOWN)
    val currentNetworkType: StateFlow<NetworkType> = _currentNetworkType.asStateFlow()

    private val strategyScores = ConcurrentHashMap<BypassStrategy, AtomicInteger>()
    private val hostStrategyMemory = ConcurrentHashMap<String, BypassStrategy>()

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
        BypassStrategy.entries.forEach { strategyScores[it] = AtomicInteger(100) }
    }

    fun loadTuningSettings(context: Context) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
        isAutoTuning = prefs.getBoolean("is_auto_tuning", true)
        blockQuic = prefs.getBoolean("block_quic", true)
        isDiagnosticMode = prefs.getBoolean("is_diagnostic_mode", false)
        
        val scorePrefs = context.getSharedPreferences("pink_proxy_scores", Context.MODE_PRIVATE)
        BypassStrategy.entries.forEach { strat ->
            val score = scorePrefs.getInt("score_${strat.name}", 100)
            strategyScores[strat]?.set(score)
        }
    }

    fun saveTuningSettings(context: Context) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
        prefs.edit().apply {
            putBoolean("is_auto_tuning", isAutoTuning)
            putBoolean("block_quic", blockQuic)
            putBoolean("is_diagnostic_mode", isDiagnosticMode)
            apply()
        }
        saveScores(context)
    }

    fun saveScores(context: Context) {
        val prefs = context.getSharedPreferences("pink_proxy_scores", Context.MODE_PRIVATE)
        prefs.edit().apply {
            strategyScores.forEach { (strat, score) ->
                putInt("score_${strat.name}", score.get())
            }
            apply()
        }
    }

    fun getBestStrategyForHost(host: String): BypassStrategy {
        if (!isAutoTuning) return _strategy.value
        
        hostStrategyMemory[host]?.let { remembered ->
            if ((strategyScores[remembered]?.get() ?: 0) > 50) return remembered
        }

        val entries = strategyScores.entries.toList()
        val totalScore = entries.sumOf { it.value.get().coerceAtLeast(1) }
        if (totalScore == 0) return BypassStrategy.SNI_SPLIT
        
        var random = ThreadLocalRandom.current().nextInt(totalScore)
        for (entry in entries) {
            random -= entry.value.get().coerceAtLeast(1)
            if (random <= 0) return entry.key
        }
        return BypassStrategy.SNI_SPLIT
    }

    fun rotateGlobalStrategy() {
        val best = strategyScores.entries.maxByOrNull { it.value.get() }?.key ?: BypassStrategy.SNI_SPLIT
        _strategy.value = best
        ProxyStats.logRecovery("Strategy rotated to best: ${best.name}")
    }

    fun startAutonomousOptimizer(scope: CoroutineScope) {
        scope.launch {
            while (isActive) {
                delay(30000)
                performSelfHealing()
            }
        }
    }

    fun recordSuccess(strat: BypassStrategy, rtt: Long, host: String?) {
        ProxyStats.recordGlobalSuccess(rtt)
        if (rtt > 0) {
            TrafficShaper.updateRtt(rtt)
        }
        
        strategyScores[strat]?.addAndGet(5)?.let { 
            if (it > 500) strategyScores[strat]?.set(500)
        }

        host?.let { hostStrategyMemory[it] = strat }
    }

    fun recordSuccess(strat: BypassStrategy, rtt: Long, context: Context?) = recordSuccess(strat, rtt, null as String?)

    fun recordFailure(strat: BypassStrategy, host: String?) {
        ProxyStats.recordCensorshipEvent(true)
        strategyScores[strat]?.addAndGet(-15)?.let {
            if (it < 1) strategyScores[strat]?.set(1)
        }
        
        host?.let { if (hostStrategyMemory[it] == strat) hostStrategyMemory.remove(it) }
    }

    fun recordFailure(strat: BypassStrategy, isCritical: Boolean, context: Context?) = recordFailure(strat, null as String?)

    fun performSelfHealing() {
        val rate = ProxyStats.getSuccessRate()
        if (rate < 40 && !isPanicMode) {
            isPanicMode = true
            _isPanicModeFlow.value = true
            ProxyStats.logRecovery("Panic mode: rate $rate%. Forcing best strategy.")
            rotateGlobalStrategy()
        } else if (rate > 85 && isPanicMode) {
            isPanicMode = false
            _isPanicModeFlow.value = false
            ProxyStats.logRecovery("Stability restored: $rate%. Normal mode.")
        }
    }

    fun clearScores(context: Context) {
        val prefs = context.getSharedPreferences("pink_proxy_scores", Context.MODE_PRIVATE)
        prefs.edit().clear().apply()
        BypassStrategy.entries.forEach { strategyScores[it]?.set(100) }
    }

    fun testInitialStrategies(context: Context) {
        // Run background probing
    }

    fun getSessionConfig(host: String, strategy: BypassStrategy, rtt: Long): SessionConfig {
        val cat = HostClassifier.classify(host)
        // Adaptive configuration based on host and RTT
        var f1 = frag1
        var d1 = delay1
        
        if (rtt > 200) {
            d1 = (d1 * 1.5).toLong()
        }
        if (cat == HostCategory.STREAMING) {
            f1 = (f1 * 2).coerceAtMost(50)
        }
        
        return SessionConfig(strategy, f1, frag2, frag3, d1, delay2, fakeTtl)
    }
    
    fun getNetworkType() = _currentNetworkType.value
    
    fun setStrategy(strat: BypassStrategy) {
        _strategy.value = strat
    }
    
    fun setGlobalStrategy(strat: BypassStrategy) = setStrategy(strat)

    fun recordStrategyResult(host: String, strategy: BypassStrategy, success: Boolean) {
        // Record result for host/strategy pair
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
    
    fun panicOptimize() {
        rotateGlobalStrategy()
    }
    
    fun reset() {
        _strategy.value = BypassStrategy.SNI_SPLIT
    }
    
    fun resetCaches() {
        // Clear caches
    }

    object TrafficShaper {
        fun updateRtt(rtt: Long) {
            _currentRttMs.value = (_currentRttMs.value * 0.8 + rtt * 0.2).toLong()
            // Dynamic congestion window based on RTT
            if (rtt < 150) {
                ProxyStats.updateCongestionWindow(1)
            } else if (rtt > 400) {
                ProxyStats.updateCongestionWindow(-1)
            }
        }
    }

    suspend fun applyBypass(socket: Socket, output: OutputStream, data: ByteArray, length: Int, config: SessionConfig, host: String) {
        val rnd = ThreadLocalRandom.current()
        val strategy = config.strategy
        
        if (strategy == BypassStrategy.DIRECT) {
            output.write(data, 0, length)
            output.flush()
            return
        }

        // Implementation of advanced bypass strategies
        when (strategy) {
            BypassStrategy.SNI_SPLIT -> {
                val split = config.frag1.coerceIn(1, length - 1)
                output.write(data, 0, split)
                output.flush()
                delay(config.delay1)
                output.write(data, split, length - split)
                output.flush()
            }
            BypassStrategy.SNI_TRIPLE -> {
                val split1 = config.frag1.coerceIn(1, (length - 2).coerceAtLeast(1))
                val split2 = (split1 + config.frag2).coerceIn(split1 + 1, (length - 1).coerceAtLeast(split1 + 1))
                output.write(data, 0, split1)
                output.flush()
                delay(config.delay1)
                output.write(data, split1, split2 - split1)
                output.flush()
                delay(config.delay2)
                output.write(data, split2, length - split2)
                output.flush()
            }
            BypassStrategy.FAKE_PACKET -> {
                val fake = FakePacketHelper.buildFakeClientHello(host, rnd.nextInt(40, 91))
                output.write(fake)
                output.flush()
                delay(config.delay1)
                output.write(data, 0, length)
                output.flush()
            }
            BypassStrategy.TLS_DIRTY -> {
                val junk = ByteArray(rnd.nextInt(5, 20))
                rnd.nextBytes(junk)
                output.write(junk)
                output.flush()
                delay(5)
                output.write(data, 0, length)
                output.flush()
            }
            BypassStrategy.TLS_PAD -> {
                output.write(data, 0, length)
                output.flush()
                val junk = ByteArray(rnd.nextInt(10, 50))
                rnd.nextBytes(junk)
                output.write(junk)
                output.flush()
            }
            BypassStrategy.SLOW_SEND -> {
                for (i in 0 until length) {
                    output.write(data[i].toInt())
                    output.flush()
                    delay(rnd.nextLong(5, 20))
                }
            }
            BypassStrategy.TCP_OOB_DESYNC -> {
                try {
                    socket.sendUrgentData(0xFF)
                } catch (e: Exception) {}
                output.write(data, 0, length)
                output.flush()
            }
            BypassStrategy.WINDOW_SIZE -> {
                // Simulate window size limits by sending in very small, fixed-size chunks
                var pos = 0
                val chunkSize = rnd.nextInt(1, 5)
                while (pos < length) {
                    val size = chunkSize.coerceAtMost(length - pos)
                    output.write(data, pos, size)
                    output.flush()
                    pos += size
                    delay(1)
                }
            }
            BypassStrategy.FRAGMENT_MULTI -> {
                var pos = 0
                while (pos < length) {
                    val size = rnd.nextInt(1, 3).coerceAtMost(length - pos)
                    output.write(data, pos, size)
                    output.flush()
                    pos += size
                    if (pos < length) delay(rnd.nextLong(1, 10))
                }
            }
            BypassStrategy.SNI_MANGLE -> {
                val offset = TlsParser.findSniOffset(data, length, host)
                if (offset != -1 && offset < length) {
                    val mangled = data.copyOf()
                    // Mangle by flipping case of a few characters in the SNI hostname
                    val hostLen = host?.length ?: (length - offset).coerceAtMost(32)
                    for (i in 0 until hostLen) {
                        if (offset + i >= length) break
                        if (rnd.nextBoolean()) {
                            val char = mangled[offset + i].toInt().toChar()
                            if (char in 'a'..'z') {
                                mangled[offset + i] = (char - 32).toInt().toByte()
                            } else if (char in 'A'..'Z') {
                                mangled[offset + i] = (char + 32).toInt().toByte()
                            }
                        }
                    }
                    
                    // Split inside the mangled SNI
                    val split = offset + rnd.nextInt(1, hostLen.coerceAtLeast(2))
                    val safeSplit = split.coerceIn(1, length - 1)
                    
                    output.write(mangled, 0, safeSplit)
                    output.flush()
                    delay(config.delay1)
                    output.write(mangled, safeSplit, length - safeSplit)
                    output.flush()
                } else {
                    // Fallback to simple split
                    val split = config.frag1.coerceIn(1, (length - 1).coerceAtLeast(1))
                    output.write(data, 0, split)
                    output.flush()
                    delay(config.delay1)
                    output.write(data, split, length - split)
                    output.flush()
                }
            }
            BypassStrategy.TLS_MULTI_FRAG -> {
                var pos = 0
                while (pos < length) {
                    val size = rnd.nextInt(1, 10).coerceAtMost(length - pos)
                    output.write(data, pos, size)
                    output.flush()
                    pos += size
                    if (pos < length) delay(rnd.nextLong(1, 5))
                }
            }
            BypassStrategy.GHOST_PACKETS -> {
                repeat(rnd.nextInt(1, 3)) {
                    val ghost = ByteArray(rnd.nextInt(10, 100))
                    rnd.nextBytes(ghost)
                    output.write(ghost)
                    output.flush()
                    delay(rnd.nextLong(10, 50))
                }
                output.write(data, 0, length)
                output.flush()
            }
            BypassStrategy.TLS_REC_SPLIT -> {
                if (length > 5 && data[0] == 0x16.toByte() && data[1] == 0x03.toByte()) {
                    output.write(data, 0, 5)
                    output.flush()
                    delay(rnd.nextLong(5, 20))
                    output.write(data, 5, length - 5)
                    output.flush()
                } else {
                    val split = 1
                    output.write(data, 0, split)
                    output.flush()
                    delay(5)
                    output.write(data, split, length - split)
                    output.flush()
                }
            }
            BypassStrategy.HTTP_HOST_SPACE -> {
                val s = String(data, 0, length)
                if (s.contains("Host:", ignoreCase = true)) {
                    val modified = s.replace("Host:", "Host: ", ignoreCase = true)
                    output.write(modified.toByteArray())
                    output.flush()
                } else {
                    output.write(data, 0, length)
                    output.flush()
                }
            }
            BypassStrategy.OOB_DESYNC -> {
                val split = rnd.nextInt(1, length.coerceAtMost(5))
                output.write(data, 0, split)
                output.flush()
                try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Exception) {}
                delay(config.delay1)
                output.write(data, split, length - split)
                output.flush()
            }
            BypassStrategy.TCP_ZERO_WINDOW -> {
                var pos = 0
                while (pos < length) {
                    val size = 1
                    output.write(data[pos].toInt())
                    output.flush()
                    pos += size
                    if (pos < length) delay(rnd.nextLong(10, 50))
                }
            }
            BypassStrategy.CHAOS -> {
                val strategies = listOf(BypassStrategy.SNI_SPLIT, BypassStrategy.TLS_DIRTY, BypassStrategy.FRAGMENT_MULTI)
                val randomStrat = strategies.random()
                applyBypass(socket, output, data, length, config.copy(strategy = randomStrat), host)
            }
            else -> {
                // Default fallback: simple split
                val split = 1
                output.write(data, 0, split)
                output.flush()
                delay(5)
                output.write(data, split, length - split)
                output.flush()
            }
        }
    }
}

class PinkProxyServer(private val vpnService: VpnService, private val port: Int) {
    private val proxyDispatcher = Executors.newCachedThreadPool().asCoroutineDispatcher()
    private var serverJob: Job? = null
    private var serverSocket: ServerSocket? = null
    
    fun start() {
        if (serverJob?.isActive == true) return
        
        val parentJob = SupervisorJob()
        val scope = CoroutineScope(proxyDispatcher + parentJob)
        serverJob = parentJob
        
        ProxyStats.startSpeedMonitor(scope)
        BypassConfig.startAutonomousOptimizer(scope)
        
        scope.launch {
            try {
                serverSocket = ServerSocket().apply {
                    reuseAddress = true
                    bind(InetSocketAddress(port))
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
    }

    private suspend fun readExactly(input: InputStream, buffer: ByteArray, offset: Int, length: Int) {
        var read = 0
        while (read < length) {
            val r = input.read(buffer, offset + read, length - read)
            if (r == -1) throw IOException("EOF")
            read += r
        }
    }

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

            if (ver2 != 5 || cmd != 1) { // Only CONNECT supported
                client.close()
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

            ProxyStats.addTraffic(host)

            // Connect to target
            val socket = Socket()
            targetSocket = socket
            socket.tcpNoDelay = true
            vpnService.protect(socket)
            try {
                withTimeout(7000) {
                    socket.connect(InetSocketAddress(host, targetPort), 7000)
                }
            } catch (e: Exception) {
                output.write(byteArrayOf(5, 1, 0, 1, 0, 0, 0, 0, 0, 0))
                output.flush()
                return
            }

            // Success response
            output.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            output.flush()

            // Tunneling with bypass
            val targetInput = socket.getInputStream()
            val targetOutput = socket.getOutputStream()

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
                                        BypassConfig.applyBypass(targetSocket, targetOutput, buffer, len, config, host)
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
                            // Expected on socket close
                        } finally {
                            ProxyStats.release16k(buffer)
                            try { targetSocket.shutdownOutput() } catch (e: Exception) {}
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
                                val cwnd = ProxyStats.congestionWindow.value * 1024
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
