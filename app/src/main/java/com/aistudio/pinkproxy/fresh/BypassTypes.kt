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
    val risk: Int = 1
) {
    FAKE_PACKET(StrategyFamily.TCP, 2, 2),
    SNI_SPLIT(StrategyFamily.FRAGMENTATION, 3, 3),
    SNI_TRIPLE(StrategyFamily.FRAGMENTATION, 4, 3),
    SNI_MANGLE(StrategyFamily.TLS, 3, 4),
    TLS_DIRTY(StrategyFamily.TLS, 2, 3),
    TLS_PAD(StrategyFamily.TLS, 2, 2),
    TLS_GREASE(StrategyFamily.TLS, 2, 1),
    TCP_OOB_DESYNC(StrategyFamily.TCP, 4, 4),
    OOB_DESYNC(StrategyFamily.TCP, 4, 4),
    GHOST_PACKETS(StrategyFamily.TCP, 3, 4),
    WINDOW_SIZE(StrategyFamily.TCP, 2, 2),
    TCP_ZERO_WINDOW(StrategyFamily.TCP, 3, 3),
    SLOW_SEND(StrategyFamily.TIMING, 4, 2),
    FRAGMENT_MULTI(StrategyFamily.FRAGMENTATION, 4, 3),
    TLS_REC_SPLIT(StrategyFamily.FRAGMENTATION, 4, 3),
    TLS_MULTI_FRAG(StrategyFamily.FRAGMENTATION, 5, 4),
    CHAOS(StrategyFamily.ADAPTIVE, 5, 5),
    TCP_MSS_CLAMP(StrategyFamily.TCP, 3, 2),
    TCP_URG_SKEW(StrategyFamily.TCP, 4, 4),
    TLS_EXT_SKEW(StrategyFamily.TLS, 3, 2),
    TCP_FAST_RETRANSMIT_SIM(StrategyFamily.TCP, 4, 4),
    TLS_REC_MANGLE(StrategyFamily.TLS, 4, 4),
    TCP_REORDER_SIM(StrategyFamily.TCP, 4, 5),
    TCP_FAST_OPEN_FAKE(StrategyFamily.TCP, 3, 3),
    TLS_PADDING_RAND(StrategyFamily.TLS, 2, 2),
    HTTP_HOST_SPACE(StrategyFamily.HTTP, 2, 3),
    TLS_REHANDSHAKE_FAKE(StrategyFamily.TLS, 4, 4),
    HTTP_RANGE_SKEW(StrategyFamily.HTTP, 3, 3),
    TCP_RST_FAKE(StrategyFamily.TCP, 5, 5),
    TLS_SNI_SKEW(StrategyFamily.TLS, 3, 3),
    HTTP_VERSION_SKEW(StrategyFamily.HTTP, 2, 2),
    TCP_TIMESTAMP_MANGLE(StrategyFamily.TCP, 3, 3),
    TLS_CIPHER_SHUFFLE(StrategyFamily.TLS, 2, 2),
    HTTP_USER_AGENT_SKEW(StrategyFamily.HTTP, 2, 2),
    TCP_URGENT_RANDOM(StrategyFamily.TCP, 4, 4),
    TLS_ALPN_SKEW(StrategyFamily.TLS, 3, 2),
    HTTP_AUTH_RANDOM(StrategyFamily.HTTP, 2, 2),
    TCP_WINDOW_SIZE_CHAOS(StrategyFamily.TCP, 4, 3),
    TLS_EXTENSION_GREASE(StrategyFamily.TLS, 2, 1),
    HTTP_HEADER_FUZZING(StrategyFamily.HTTP, 3, 3),
    TCP_REORDER_CHAOS(StrategyFamily.TCP, 4, 5),
    TLS_HELLO_JUNK(StrategyFamily.TLS, 4, 4),
    HTTP_METHOD_FAKE(StrategyFamily.HTTP, 3, 3),
    TLS_LEGACY_HELLOS(StrategyFamily.TLS, 3, 3),
    TCP_KEEP_ALIVE_FAKE(StrategyFamily.TCP, 2, 2),
    QUIC_INITIAL_FAKE(StrategyFamily.QUIC, 3, 2),
    QUIC_RST_SKEW(StrategyFamily.QUIC, 4, 3),
    QUIC_MTU_PROBE(StrategyFamily.QUIC, 3, 3),
    DNS_OVER_TCP(StrategyFamily.DNS, 2, 1),
    DNS_NOISE(StrategyFamily.DNS, 3, 3),
    DNS_CASE_MANGLE(StrategyFamily.DNS, 2, 2),
    ADAPTIVE_CHUNK(StrategyFamily.ADAPTIVE, 3, 2),
    HTTP_HOST_CASE_MANGLE(StrategyFamily.HTTP, 2, 3),
    TLS_SESSION_TICKET_SKEW(StrategyFamily.TLS, 3, 2),
    TLS_MULTI_SNI(StrategyFamily.TLS, 4, 4),
    HTTP_CHUNKED_FAKE(StrategyFamily.HTTP, 4, 3),
    TCP_WINDOW_RESTRICT(StrategyFamily.TCP, 3, 2),
    TLS_COMPRESSION_FAKE(StrategyFamily.TLS, 3, 3),
    TCP_WINDOW_SCAN(StrategyFamily.TCP, 4, 3),
    HTTP_PIPELINE_FAKE(StrategyFamily.HTTP, 4, 4),
    TLS_CHROME_HELLO_FAKE(StrategyFamily.TLS, 2, 1),
    TLS_FIREFOX_HELLO_FAKE(StrategyFamily.TLS, 2, 1),
    TLS_13_HELLO_FAKE(StrategyFamily.TLS, 2, 1),
    TCP_REORDER_DESYNC(StrategyFamily.TCP, 4, 4),
    TLS_ECH_FAKE(StrategyFamily.TLS, 4, 3),
    TLS_SESSION_ID_RAND(StrategyFamily.TLS, 2, 2),
    TCP_ACK_DELAY(StrategyFamily.TIMING, 4, 3),
    TLS_MIXED_CASE_SNI(StrategyFamily.TLS, 3, 2),
    TLS_0RTT_FAKE(StrategyFamily.TLS, 4, 3),
    HTTP2_PREAMBLE_FAKE(StrategyFamily.HTTP, 3, 3),
    TLS_GREASE_SKEW(StrategyFamily.TLS, 3, 2),
    TLS_SNI_SYMMETRIC_SPLIT(StrategyFamily.TLS, 3, 2),
    HTTP_OOB_INJECT(StrategyFamily.HTTP, 4, 4),
    QUIC_VERSION_NEGOTIATION_SKEW(StrategyFamily.QUIC, 3, 2),
    TCP_FRAG_OOB(StrategyFamily.TCP, 5, 4),
    PROTOCOL_CONFUSION_SSH(StrategyFamily.TCP, 3, 2),
    PROTOCOL_CONFUSION_BITTORRENT(StrategyFamily.TCP, 3, 2),
    TCP_TOS_MANGLE(StrategyFamily.TCP, 2, 1),
    WS_HANDSHAKE_FAKE(StrategyFamily.HTTP, 3, 3),
    SSH_HANDSHAKE_FAKE(StrategyFamily.TCP, 3, 3),
    UDP_DTLS_FAKE(StrategyFamily.QUIC, 3, 2),
    HTTP_KEEP_ALIVE_FAKE(StrategyFamily.HTTP, 2, 2),
    UDP_GHOST_SKEW(StrategyFamily.UDP, 3, 3),
    UDP_FRAGMENT_SKEW(StrategyFamily.UDP, 4, 4),
    UDP_STUTTER(StrategyFamily.TIMING, 2, 2),
    TLS_CLIENT_HELLO_GREASE(StrategyFamily.TLS, 2, 1),
    TLS_CLIENT_HELLO_PAD(StrategyFamily.TLS, 3, 1),
    TCP_DATA_OOB_SKEW(StrategyFamily.TCP, 3, 2),
    TCP_SACK_FAKE(StrategyFamily.TCP, 3, 3),
    TLS_HANDSHAKE_RANDOM_PADDING(StrategyFamily.TLS, 4, 2),
    HTTP_HOST_REORDER(StrategyFamily.HTTP, 2, 3),
    TLS_CLIENT_HELLO_REORDER(StrategyFamily.TLS, 4, 3),
    TCP_WINDOW_SIZE_SKEW(StrategyFamily.TCP, 2, 2),
    TCP_DATA_REPETITION(StrategyFamily.TCP, 4, 2),
    TLS_SNI_SPLIT(StrategyFamily.TLS, 4, 4),
    UDP_STUN_FAKE(StrategyFamily.UDP, 2, 4),
    TCP_WINDOW_CLAMPING(StrategyFamily.TCP, 2, 2),
    TLS_CLIENT_HELLO_CHOP(StrategyFamily.TLS, 5, 4),
    UDP_FAKE_DTLS(StrategyFamily.UDP, 3, 4),
    TLS_APP_DATA_SPLIT(StrategyFamily.TLS, 4, 2),
    HTTP_HOST_MANGLE(StrategyFamily.HTTP, 3, 3),
    HTTP_FRAGMENT(StrategyFamily.HTTP, 4, 2),
    TCP_SACK_PANIC(StrategyFamily.TCP, 3, 2),
    TCP_GHOST_SKEW(StrategyFamily.TCP, 4, 3),
    TLS_CLIENT_HELLO_SHUFFLE(StrategyFamily.TLS, 5, 4),
    UDP_NOISE_PAD(StrategyFamily.UDP, 3, 4),
    DIRECT(StrategyFamily.DIRECT, 0, 0)
}

enum class NetworkType { WIFI, MOBILE, UNKNOWN }

enum class HostCategory { STREAMING, SOCIAL, MESSENGER, SEARCH, AI, FINANCE, CDN, NEWS, GAMING, SHOPPING, DEV, OTHER }

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
                _pool64kSize.value = bufferPool64k.size
                
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
             val lastRtt = _speedHistory.value.firstOrNull() ?: rtt
             val jitter = Math.abs(rtt - lastRtt)
             val jitterPenalty = (jitter / 10).coerceAtMost(20)
             _stabilityScore.update { (it * 0.95 + (100 - jitterPenalty) * 0.05).toInt().coerceIn(0, 100) }
        }
        _successRate.update { (it * 0.98 + 100 * 0.02).toInt().coerceIn(0, 100) }
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

