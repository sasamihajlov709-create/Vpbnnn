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

enum class StrategyFamily {
    TCP, TLS, HTTP, TIMING, FRAGMENTATION, ADAPTIVE, DNS, QUIC, GENERIC, UDP, DIRECT
}

enum class BypassStrategy(
    val family: StrategyFamily = StrategyFamily.GENERIC,
    val cost: Int = 1,
    val risk: Int = 1,
    val group: StrategyGroup = StrategyGroup.MEDIUM
) {
    FAKE_PACKET(StrategyFamily.TCP, 2, 2, StrategyGroup.HEAVY),
    SNI_SPLIT(StrategyFamily.FRAGMENTATION, 3, 3, StrategyGroup.MEDIUM),
    SNI_TRIPLE(StrategyFamily.FRAGMENTATION, 4, 3, StrategyGroup.HEAVY),
    SNI_MANGLE(StrategyFamily.TLS, 3, 4, StrategyGroup.EXTREME),
    TLS_DIRTY(StrategyFamily.TLS, 2, 3, StrategyGroup.MEDIUM),
    TLS_PAD(StrategyFamily.TLS, 2, 2, StrategyGroup.LIGHT),
    TLS_GREASE(StrategyFamily.TLS, 2, 1, StrategyGroup.LIGHT),
    TCP_OOB_DESYNC(StrategyFamily.TCP, 4, 4, StrategyGroup.EXTREME),
    OOB_DESYNC(StrategyFamily.TCP, 4, 4, StrategyGroup.EXTREME),
    GHOST_PACKETS(StrategyFamily.TCP, 3, 4, StrategyGroup.EXTREME),
    WINDOW_SIZE_MANGLE(StrategyFamily.TCP, 2, 2, StrategyGroup.MEDIUM),
    TCP_ZERO_WINDOW_STALL(StrategyFamily.TCP, 3, 3, StrategyGroup.HEAVY),
    SLOW_SEND(StrategyFamily.TIMING, 4, 2, StrategyGroup.MEDIUM),
    FRAGMENT_MULTI(StrategyFamily.FRAGMENTATION, 4, 3, StrategyGroup.HEAVY),
    TLS_REC_SPLIT(StrategyFamily.FRAGMENTATION, 4, 3, StrategyGroup.HEAVY),
    TLS_MULTI_FRAG(StrategyFamily.FRAGMENTATION, 5, 4, StrategyGroup.EXTREME),
    CHAOS(StrategyFamily.ADAPTIVE, 5, 5, StrategyGroup.EXTREME),
    TCP_MSS_CLAMP(StrategyFamily.TCP, 3, 2, StrategyGroup.LIGHT),
    TCP_URG_SKEW(StrategyFamily.TCP, 4, 4, StrategyGroup.HEAVY),
    TLS_EXT_SKEW(StrategyFamily.TLS, 3, 2, StrategyGroup.MEDIUM),
    TCP_FAST_RETRANSMIT_SIM(StrategyFamily.TCP, 4, 4, StrategyGroup.HEAVY),
    TLS_REC_MANGLE(StrategyFamily.TLS, 4, 4, StrategyGroup.EXTREME),
    TCP_REORDER_SIM(StrategyFamily.TCP, 4, 5, StrategyGroup.EXTREME),
    TCP_FAST_OPEN_FAKE(StrategyFamily.TCP, 3, 3, StrategyGroup.MEDIUM),
    TLS_PADDING_RAND(StrategyFamily.TLS, 2, 2, StrategyGroup.LIGHT),
    HTTP_HOST_SPACE(StrategyFamily.HTTP, 2, 3, StrategyGroup.MEDIUM),
    TLS_REHANDSHAKE_FAKE(StrategyFamily.TLS, 4, 4, StrategyGroup.HEAVY),
    HTTP_RANGE_SKEW(StrategyFamily.HTTP, 3, 3, StrategyGroup.MEDIUM),
    TCP_RST_FAKE(StrategyFamily.TCP, 5, 5, StrategyGroup.EXTREME),
    TLS_SNI_SKEW(StrategyFamily.TLS, 3, 3, StrategyGroup.HEAVY),
    HTTP_VERSION_SKEW(StrategyFamily.HTTP, 2, 2, StrategyGroup.LIGHT),
    TCP_TIMESTAMP_MANGLE(StrategyFamily.TCP, 3, 3, StrategyGroup.MEDIUM),
    TLS_CIPHER_SHUFFLE(StrategyFamily.TLS, 2, 2, StrategyGroup.LIGHT),
    HTTP_USER_AGENT_SKEW(StrategyFamily.HTTP, 2, 2, StrategyGroup.LIGHT),
    TCP_URGENT_RANDOM(StrategyFamily.TCP, 4, 4, StrategyGroup.HEAVY),
    TLS_ALPN_SKEW(StrategyFamily.TLS, 3, 2, StrategyGroup.MEDIUM),
    HTTP_AUTH_RANDOM(StrategyFamily.HTTP, 2, 2, StrategyGroup.LIGHT),
    TLS_EXTENSION_GREASE(StrategyFamily.TLS, 2, 1, StrategyGroup.LIGHT),
    HTTP_HEADER_FUZZING(StrategyFamily.HTTP, 3, 3, StrategyGroup.HEAVY),
    TCP_REORDER_CHAOS(StrategyFamily.TCP, 4, 5, StrategyGroup.EXTREME),
    TLS_HELLO_JUNK(StrategyFamily.TLS, 4, 4, StrategyGroup.EXTREME),
    HTTP_METHOD_FAKE(StrategyFamily.HTTP, 3, 3, StrategyGroup.MEDIUM),
    TLS_LEGACY_HELLOS(StrategyFamily.TLS, 3, 3, StrategyGroup.MEDIUM),
    TCP_KEEP_ALIVE_FAKE(StrategyFamily.TCP, 2, 2, StrategyGroup.LIGHT),
    QUIC_RST_SKEW(StrategyFamily.QUIC, 4, 3, StrategyGroup.HEAVY),
    QUIC_MTU_PROBE(StrategyFamily.QUIC, 3, 3, StrategyGroup.MEDIUM),
    DNS_OVER_TCP(StrategyFamily.DNS, 2, 1, StrategyGroup.LIGHT),
    DNS_NOISE(StrategyFamily.DNS, 3, 3, StrategyGroup.MEDIUM),
    DNS_CASE_MANGLE(StrategyFamily.DNS, 2, 2, StrategyGroup.LIGHT),
    ADAPTIVE_CHUNK(StrategyFamily.ADAPTIVE, 3, 2, StrategyGroup.MEDIUM),
    HTTP_HOST_CASE_MANGLE(StrategyFamily.HTTP, 2, 3, StrategyGroup.MEDIUM),
    TLS_SESSION_TICKET_SKEW(StrategyFamily.TLS, 3, 2, StrategyGroup.MEDIUM),
    TLS_MULTI_SNI(StrategyFamily.TLS, 4, 4, StrategyGroup.HEAVY),
    HTTP_CHUNKED_FAKE(StrategyFamily.HTTP, 4, 3, StrategyGroup.HEAVY),
    TCP_WINDOW_RESTRICT(StrategyFamily.TCP, 3, 2, StrategyGroup.MEDIUM),
    TLS_COMPRESSION_FAKE(StrategyFamily.TLS, 3, 3, StrategyGroup.HEAVY),
    TCP_WINDOW_SCAN(StrategyFamily.TCP, 4, 3, StrategyGroup.HEAVY),
    HTTP_PIPELINE_FAKE(StrategyFamily.HTTP, 4, 4, StrategyGroup.EXTREME),
    TLS_CHROME_HELLO_FAKE(StrategyFamily.TLS, 2, 1, StrategyGroup.LIGHT),
    TLS_FIREFOX_HELLO_FAKE(StrategyFamily.TLS, 2, 1, StrategyGroup.LIGHT),
    TLS_13_HELLO_FAKE(StrategyFamily.TLS, 2, 1, StrategyGroup.LIGHT),
    TCP_REORDER_DESYNC(StrategyFamily.TCP, 4, 4, StrategyGroup.EXTREME),
    TLS_ECH_FAKE(StrategyFamily.TLS, 4, 3, StrategyGroup.HEAVY),
    TLS_SESSION_ID_RAND(StrategyFamily.TLS, 2, 2, StrategyGroup.LIGHT),
    TCP_ACK_DELAY(StrategyFamily.TIMING, 4, 3, StrategyGroup.MEDIUM),
    TLS_MIXED_CASE_SNI(StrategyFamily.TLS, 3, 2, StrategyGroup.MEDIUM),
    TLS_0RTT_FAKE(StrategyFamily.TLS, 4, 3, StrategyGroup.HEAVY),
    HTTP2_PREAMBLE_FAKE(StrategyFamily.HTTP, 3, 3, StrategyGroup.MEDIUM),
    TLS_GREASE_SKEW(StrategyFamily.TLS, 3, 2, StrategyGroup.MEDIUM),
    TLS_SNI_SYMMETRIC_SPLIT(StrategyFamily.TLS, 3, 2, StrategyGroup.MEDIUM),
    HTTP_OOB_INJECT(StrategyFamily.HTTP, 4, 4, StrategyGroup.EXTREME),
    QUIC_VERSION_NEGOTIATION_SKEW(StrategyFamily.QUIC, 3, 2, StrategyGroup.MEDIUM),
    TCP_FRAG_OOB(StrategyFamily.TCP, 5, 4, StrategyGroup.EXTREME),
    PROTOCOL_CONFUSION_SSH(StrategyFamily.TCP, 3, 2, StrategyGroup.MEDIUM),
    PROTOCOL_CONFUSION_BITTORRENT(StrategyFamily.TCP, 3, 2, StrategyGroup.MEDIUM),
    TCP_TOS_MANGLE(StrategyFamily.TCP, 2, 1, StrategyGroup.LIGHT),
    WS_HANDSHAKE_FAKE(StrategyFamily.HTTP, 3, 3, StrategyGroup.MEDIUM),
    SSH_HANDSHAKE_FAKE(StrategyFamily.TCP, 3, 3, StrategyGroup.MEDIUM),
    UDP_DTLS_FAKE(StrategyFamily.QUIC, 3, 2, StrategyGroup.MEDIUM),
    HTTP_KEEP_ALIVE_FAKE(StrategyFamily.HTTP, 2, 2, StrategyGroup.LIGHT),
    UDP_GHOST_SKEW(StrategyFamily.UDP, 3, 3, StrategyGroup.HEAVY),
    UDP_FRAGMENT_SKEW(StrategyFamily.UDP, 4, 4, StrategyGroup.EXTREME),
    UDP_STUTTER(StrategyFamily.TIMING, 2, 2, StrategyGroup.MEDIUM),
    TLS_CLIENT_HELLO_GREASE(StrategyFamily.TLS, 2, 1, StrategyGroup.LIGHT),
    TLS_CLIENT_HELLO_PAD(StrategyFamily.TLS, 3, 1, StrategyGroup.MEDIUM),
    TCP_DATA_OOB_SKEW(StrategyFamily.TCP, 3, 2, StrategyGroup.MEDIUM),
    TCP_SACK_FAKE(StrategyFamily.TCP, 3, 3, StrategyGroup.HEAVY),
    TLS_HANDSHAKE_RANDOM_PADDING(StrategyFamily.TLS, 4, 2, StrategyGroup.HEAVY),
    HTTP_HOST_REORDER(StrategyFamily.HTTP, 2, 3, StrategyGroup.MEDIUM),
    TLS_CLIENT_HELLO_REORDER(StrategyFamily.TLS, 4, 3, StrategyGroup.EXTREME),
    TCP_WINDOW_SIZE_SKEW(StrategyFamily.TCP, 2, 2, StrategyGroup.MEDIUM),
    TCP_DATA_REPETITION(StrategyFamily.TCP, 4, 2, StrategyGroup.HEAVY),
    TLS_SNI_SPLIT(StrategyFamily.TLS, 4, 4, StrategyGroup.EXTREME),
    UDP_STUN_FAKE(StrategyFamily.UDP, 2, 4, StrategyGroup.MEDIUM),
    TCP_WINDOW_CLAMPING(StrategyFamily.TCP, 2, 2, StrategyGroup.MEDIUM),
    TLS_CLIENT_HELLO_CHOP(StrategyFamily.TLS, 5, 4, StrategyGroup.EXTREME),
    UDP_FAKE_DTLS(StrategyFamily.UDP, 3, 4, StrategyGroup.HEAVY),
    TLS_APP_DATA_SPLIT(StrategyFamily.TLS, 4, 2, StrategyGroup.MEDIUM),
    HTTP_HOST_MANGLE(StrategyFamily.HTTP, 3, 3, StrategyGroup.HEAVY),
    HTTP_FRAGMENT(StrategyFamily.HTTP, 4, 2, StrategyGroup.HEAVY),
    TCP_SACK_PANIC(StrategyFamily.TCP, 3, 2, StrategyGroup.MEDIUM),
    TCP_GHOST_SKEW(StrategyFamily.TCP, 4, 3, StrategyGroup.HEAVY),
    TLS_CLIENT_HELLO_SHUFFLE(StrategyFamily.TLS, 5, 4, StrategyGroup.EXTREME),
    UDP_NOISE_PAD(StrategyFamily.UDP, 3, 4, StrategyGroup.HEAVY),
    TLS_RECORD_FRAGMENTATION(StrategyFamily.TLS, 4, 3, StrategyGroup.HEAVY),
    QUIC_INITIAL_FAKE(StrategyFamily.UDP, 3, 4, StrategyGroup.HEAVY),
    HTTP_HOST_SMUGGLE(StrategyFamily.HTTP, 3, 3, StrategyGroup.HEAVY),
    UDP_WIREGUARD_FAKE(StrategyFamily.UDP, 3, 3, StrategyGroup.MEDIUM),
    UDP_IKE_FAKE(StrategyFamily.UDP, 3, 3, StrategyGroup.MEDIUM),
    UDP_DHCP_FAKE(StrategyFamily.UDP, 3, 3, StrategyGroup.MEDIUM),
    PROTOCOL_CONFUSION_HTTP(StrategyFamily.TCP, 3, 3, StrategyGroup.HEAVY),
    TCP_SMALL_CHUNKS(StrategyFamily.FRAGMENTATION, 4, 3, StrategyGroup.HEAVY),
    UDP_TELEGRAM_FAKE(StrategyFamily.UDP, 3, 2, StrategyGroup.MEDIUM),
    UDP_DISCORD_FAKE(StrategyFamily.UDP, 3, 2, StrategyGroup.MEDIUM),
    TCP_RANDOM_PADDING(StrategyFamily.TCP, 2, 1, StrategyGroup.LIGHT),
    TLS_RECORD_PADDING(StrategyFamily.TLS, 2, 2, StrategyGroup.MEDIUM),
    UDP_HIGH_VOL_PACING(StrategyFamily.UDP, 2, 1, StrategyGroup.LIGHT),
    UDP_ZERO_LEN_SKEW(StrategyFamily.UDP, 2, 1, StrategyGroup.LIGHT),
    TCP_WINDOW_SIZE_CHAOS(StrategyFamily.TCP, 4, 3, StrategyGroup.HEAVY),
    TCP_MSS_CLUMPING(StrategyFamily.TCP, 3, 2, StrategyGroup.HEAVY),
    TLS_CLIENT_HELLO_GREASE_RANDOM(StrategyFamily.TLS, 2, 2, StrategyGroup.LIGHT),
    DIRECT(StrategyFamily.DIRECT, 0, 0, StrategyGroup.LIGHT)
}

enum class NetworkType { WIFI, MOBILE, UNKNOWN }

enum class HostCategory { STREAMING, SOCIAL, MESSENGER, SEARCH, AI, FINANCE, CDN, NEWS, GAMING, SHOPPING, DEV, AD, OTHER }

enum class DpiType {
    NONE,
    TCP_RESET,
    UDP_BLOCK,
    TLS_SNI_BLOCK,
    DNS_POISONING,
    CONNECTION_TIMEOUT,
    HTTP_BLOCK
}

object ProxyStats {
    private val _currentDpiType = MutableStateFlow(DpiType.NONE)
    val currentDpiType: StateFlow<DpiType> = _currentDpiType.asStateFlow()

    fun recordDpiEvent(type: DpiType) {
        _currentDpiType.value = type
        recordCensorshipEvent(true)
        logRecovery("Detected censorship type: $type")
    }
    
    fun recordDnsFailure() {
        _dnsFailureCount.update { it + 1 }
        recordCensorshipEvent(true)
    }
    
    fun clearDpiType() {
        _currentDpiType.value = DpiType.NONE
    }

    private val _lastLatency = MutableStateFlow(0L)
    val lastLatency: StateFlow<Long> = _lastLatency.asStateFlow()

    private val _jitter = MutableStateFlow(0L)
    val jitter: StateFlow<Long> = _jitter.asStateFlow()

    fun updateLatency(ms: Long) {
        val old = _lastLatency.value
        if (old > 0) {
            val diff = Math.abs(ms - old)
            _jitter.value = (_jitter.value * 3 + diff) / 4 // Moving average
        }
        _lastLatency.value = ms
    }

    private val bufferPool8k = LinkedBlockingQueue<ByteArray>(256)
    private val bufferPool16k = LinkedBlockingQueue<ByteArray>(128)
    private val bufferPool64k = LinkedBlockingQueue<ByteArray>(64)

    fun obtain8k(): ByteArray = bufferPool8k.poll() ?: ByteArray(8192)
    fun release8k(buf: ByteArray) { bufferPool8k.offer(buf) }
    fun obtain16k(): ByteArray = bufferPool16k.poll() ?: ByteArray(16384)
    fun release16k(buf: ByteArray) { bufferPool16k.offer(buf) }
    fun obtain64k(): ByteArray = bufferPool64k.poll() ?: ByteArray(65536)
    fun release64k(buf: ByteArray) { bufferPool64k.offer(buf) }

    fun releaseAllPools() {
        bufferPool8k.clear()
        bufferPool16k.clear()
        bufferPool64k.clear()
    }

    private val _bytesTransferred = MutableStateFlow(0L)
    val bytesTransferred: StateFlow<Long> = _bytesTransferred.asStateFlow()
    
    private val rawBytesTransferred = AtomicLong(0)
    
    fun updateBytes(delta: Long) {
        rawBytesTransferred.addAndGet(delta)
    }

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

    fun recordCensorshipEvent(isFailure: Boolean) {
        if (isFailure) {
            _errors.update { it + 1 }
            _successRate.update { (it * 0.9).toInt().coerceIn(0, 100) }
            _censorshipIntensity.update { (it + 5).coerceAtMost(100) }
        } else {
            _censorshipIntensity.update { (it - 1).coerceAtLeast(0) }
        }
    }

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

    private val _pool64kSize = MutableStateFlow(0)
    val pool64kSize: StateFlow<Int> = _pool64kSize.asStateFlow()

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

    private val _maxMss = MutableStateFlow(1460)
    val maxMss: StateFlow<Int> = _maxMss.asStateFlow()

    fun recordMssFailure() {
        _maxMss.update { (it - 64).coerceAtLeast(512) }
        logRecovery("MTU auto-correction: reducing MSS to ${_maxMss.value}")
    }

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
        RecoveryManager.handleEvent(RecoveryEvent.PROXY_UNREACHABLE, "Manual trigger: $reason")
    }
    
    fun reset(clearLog: Boolean) {
        rawBytesTransferred.set(0)
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
            var lastBytes = rawBytesTransferred.get()
            var lastCleanup = System.currentTimeMillis()
            while (isActive) {
                delay(1000)
                val now = System.currentTimeMillis()
                
                if (now - lastCleanup > 300000) { // Every 5 minutes
                    DnsCacheManager.ageHeatmap()
                    DnsCacheManager.clearExpired()
                    lastCleanup = now
                }

                val currentBytes = rawBytesTransferred.get()
                _bytesTransferred.value = currentBytes
                val speed = (currentBytes - lastBytes).coerceAtLeast(0)
                _speedBytesPerSecond.value = speed
                
                // Adaptive Signal Quality calculation
                val baseQual = _successRate.value.coerceIn(0, 100)
                val stabPenalty = (100 - _stabilityScore.value) / 2
                val panicPenalty = if (BypassConfig.isPanicModeFlow.value) 15 else 0
                val intensityPenalty = (ProxyStats.censorshipIntensity.value / 10).coerceAtMost(10)
                
                val finalQual = (baseQual - stabPenalty - panicPenalty - intensityPenalty).coerceIn(0, 100)
                _signalQuality.value = finalQual

                _speedHistory.update { current ->
                    val newList = ArrayList<Long>(60)
                    newList.add(speed)
                    if (current.size > 59) {
                        newList.addAll(current.subList(0, 59))
                    } else {
                        newList.addAll(current)
                    }
                    newList
                }
                
                lastBytes = currentBytes
                
                _pool8kSize.value = bufferPool8k.size
                _pool16kSize.value = bufferPool16k.size
                _pool64kSize.value = bufferPool64k.size
                
                // Adaptive signal quality based on success rate and intensity
                val quality = (successRate.value - censorshipIntensity.value / 2).coerceIn(0, 100)
                _signalQuality.value = quality
            }
        }
    }

    val currentJitterFactor: Double get() = if (censorshipIntensity.value > 50) 0.5 else 0.1

    fun formatBytes(bytes: Long): String {
        if (bytes <= 0) return "0 B"
        if (bytes < 1024) return "$bytes B"
        val exp = (Math.log(bytes.toDouble()) / Math.log(1024.0)).toInt()
        val pre = "KMGTPE"[exp - 1].toString()
        return String.format(Locale.ROOT, "%.1f %sB", bytes / Math.pow(1024.0, exp.toDouble()), pre)
    }

    fun recordGlobalSuccess(rtt: Long) {
        if (rtt > 0) {
             val lastRtt = _lastLatency.value
             val jitter = Math.abs(rtt - lastRtt)
             val jitterPenalty = (jitter / 15).coerceAtMost(25)
             _stabilityScore.update { (it * 0.97 + (100 - jitterPenalty) * 0.03).toInt().coerceIn(0, 100) }
             updateLatency(rtt)
        }
        _successRate.update { (it * 0.99 + 100 * 0.01).toInt().coerceIn(0, 100) }
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
            h.contains("youtube") || h.contains("netflix") || h.contains("twitch") || h.contains("googlevideo") || h.contains("vimeo") -> HostCategory.STREAMING
            h.contains("facebook") || h.contains("instagram") || h.contains("twitter") || h.contains("tiktok") || h.contains("linkedin") || h.contains("reddit") -> HostCategory.SOCIAL
            h.contains("whatsapp") || h.contains("telegram") || h.contains("discord") || h.contains("signal.org") || h.contains("slack") -> HostCategory.MESSENGER
            h.contains("google") || h.contains("bing") || h.contains("duckduckgo") || h.contains("yahoo") || h.contains("baidu") || h.contains("yandex") -> HostCategory.SEARCH
            h.contains("openai") || h.contains("anthropic") || h.contains("mistral") || h.contains("perplexity") || h.contains("gemini") || h.contains("chatgpt") || h.contains("claude") -> HostCategory.AI
            h.contains("bank") || h.contains("crypto") || h.contains("binance") || h.contains("paypal") || h.contains("visa") || h.contains("stripe") || h.contains("wallet") || h.contains("coinbase") || h.contains("revolut") -> HostCategory.FINANCE
            h.contains("github") || h.contains("gitlab") || h.contains("npm") || h.contains("docker") || h.contains("stackoverflow") || h.contains("jetbrains") || h.contains("android") -> HostCategory.DEV
            h.contains("cloudflare") || h.contains("akamai") || h.contains("fastly") || h.contains("cloudfront") -> HostCategory.CDN
            h.contains("steam") || h.contains("epicgames") || h.contains("roblox") || h.contains("playstation") || h.contains("xbox") -> HostCategory.GAMING
            h.contains("amazon") || h.contains("ebay") || h.contains("aliexpress") || h.contains("shopify") -> HostCategory.SHOPPING
            h.contains("ads.") || h.contains("doubleclick") || h.contains("adservice") || h.contains("analytics") || h.contains("telemetry") || h.contains("metrics") -> HostCategory.AD
            else -> HostCategory.OTHER
        }
    }
}

data class SessionConfig(val strategy: BypassStrategy, val frag1: Int, val frag2: Int, val frag3: Int, val delay1: Long, val delay2: Long, val fakeTtl: Int)

data class StrategyMetric(val strategy: BypassStrategy, val score: Int, val successes: Long, val failures: Long, val avgRtt: Long)

enum class StrategyGroup { LIGHT, MEDIUM, HEAVY, EXTREME }

