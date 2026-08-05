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

enum class FailureReason {
    TIMEOUT,
    TCP_RESET,
    SSL_HANDSHAKE_ERROR,
    CONNECTION_REFUSED,
    CENSORSHIP_STALL,
    DNS_POISONED,
    MTU_EXCEEDED,
    UNKNOWN
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
    TCP_MSS_CLAMP(StrategyFamily.TCP, 3, 2, StrategyGroup.LIGHT),
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
    TLS_SESSION_ID_MANGLE(StrategyFamily.TLS, 3, 2, StrategyGroup.MEDIUM),
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
    TLS_SESSION_ID_RAND(StrategyFamily.TLS, 2, 2, StrategyGroup.LIGHT),
    TCP_ACK_DELAY(StrategyFamily.TIMING, 4, 3, StrategyGroup.MEDIUM),
    TCP_URGENT_SKEW(StrategyFamily.TCP, 4, 4, StrategyGroup.HEAVY),
    TCP_WINDOW_SIZE_SKEW(StrategyFamily.TCP, 2, 2, StrategyGroup.MEDIUM),
    TLS_MIXED_CASE_SNI(StrategyFamily.TLS, 3, 2, StrategyGroup.MEDIUM),
    TCP_DATA_REPETITION(StrategyFamily.TCP, 4, 2, StrategyGroup.HEAVY),
    TLS_SNI_SPLIT(StrategyFamily.TLS, 4, 4, StrategyGroup.EXTREME),
    UDP_STUN_FAKE(StrategyFamily.UDP, 2, 4, StrategyGroup.MEDIUM),
    TCP_WINDOW_CLAMPING(StrategyFamily.TCP, 2, 2, StrategyGroup.MEDIUM),
    TLS_CLIENT_HELLO_CHOP(StrategyFamily.TLS, 5, 4, StrategyGroup.EXTREME),
    UDP_FAKE_DTLS(StrategyFamily.UDP, 3, 4, StrategyGroup.HEAVY),
    UDP_FAKE_SESSION(StrategyFamily.UDP, 3, 3, StrategyGroup.MEDIUM),
    TLS_APP_DATA_SPLIT(StrategyFamily.TLS, 4, 2, StrategyGroup.MEDIUM),
    HTTP_HOST_MANGLE(StrategyFamily.HTTP, 3, 3, StrategyGroup.HEAVY),
    HTTP_FRAGMENT(StrategyFamily.HTTP, 4, 2, StrategyGroup.HEAVY),
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
    PROTOCOL_CONFUSION_QUIC(StrategyFamily.UDP, 3, 3, StrategyGroup.HEAVY),
    PROTOCOL_CONFUSION_DTLS(StrategyFamily.UDP, 3, 3, StrategyGroup.HEAVY),
    TCP_SMALL_CHUNKS(StrategyFamily.FRAGMENTATION, 4, 3, StrategyGroup.HEAVY),
    UDP_TELEGRAM_FAKE(StrategyFamily.UDP, 3, 2, StrategyGroup.MEDIUM),
    UDP_DISCORD_FAKE(StrategyFamily.UDP, 3, 2, StrategyGroup.MEDIUM),
    TCP_RANDOM_PADDING(StrategyFamily.TCP, 2, 1, StrategyGroup.LIGHT),
    TLS_RECORD_PADDING(StrategyFamily.TLS, 2, 2, StrategyGroup.MEDIUM),
    UDP_HIGH_VOL_PACING(StrategyFamily.UDP, 2, 1, StrategyGroup.LIGHT),
    UDP_ZERO_LEN_SKEW(StrategyFamily.UDP, 2, 1, StrategyGroup.LIGHT),
    UDP_NOISE_CHAOS(StrategyFamily.UDP, 3, 3, StrategyGroup.HEAVY),
    TCP_MSS_CLUMPING(StrategyFamily.TCP, 3, 2, StrategyGroup.HEAVY),
    TLS_CLIENT_HELLO_GREASE_RANDOM(StrategyFamily.TLS, 2, 2, StrategyGroup.LIGHT),
    HTTP_HOST_TAB_MANGLE(StrategyFamily.HTTP, 2, 3, StrategyGroup.MEDIUM),
    TLS_SNI_NULL_EXT(StrategyFamily.TLS, 3, 2, StrategyGroup.MEDIUM),
    TLS_CLIENT_HELLO_PAD_EXTREME(StrategyFamily.TLS, 4, 2, StrategyGroup.EXTREME),
    TLS_EXTENSION_SHUFFLE(StrategyFamily.TLS, 3, 2, StrategyGroup.MEDIUM),
    UDP_QUIC_SKEW(StrategyFamily.UDP, 3, 3, StrategyGroup.MEDIUM),
    UDP_DATA_FRAG(StrategyFamily.UDP, 2, 2, StrategyGroup.LIGHT),
    UDP_FAKE_TRAFFIC(StrategyFamily.UDP, 3, 2, StrategyGroup.MEDIUM),
    UDP_IP_FRAG(StrategyFamily.UDP, 4, 3, StrategyGroup.HEAVY),
    QUIC_INITIAL_PADDING_EXTREME(StrategyFamily.UDP, 4, 3, StrategyGroup.EXTREME),
    QUIC_INITIAL_FRAGMENTATION(StrategyFamily.UDP, 5, 4, StrategyGroup.EXTREME),
    UDP_IPv6_FRAG(StrategyFamily.UDP, 3, 3, StrategyGroup.MEDIUM),
    ECH_FRAG(StrategyFamily.TLS, 6, 6, StrategyGroup.EXTREME),
    QUIC_FORCE_FRAG(StrategyFamily.UDP, 5, 5, StrategyGroup.EXTREME),
    TCP_HANDSHAKE_CHAOS(StrategyFamily.TCP, 5, 5, StrategyGroup.EXTREME),
    TCP_MSS_CLAMPER(StrategyFamily.TCP, 3, 2, StrategyGroup.MEDIUM),
    HTTP_CONNECTION_CLOSE_SKEW(StrategyFamily.HTTP, 1, 2, StrategyGroup.LIGHT),
    HTTP_MULTI_LINE_MANGLE(StrategyFamily.HTTP, 3, 3, StrategyGroup.HEAVY),
    HTTP_HOST_FOLDING(StrategyFamily.HTTP, 3, 2, StrategyGroup.MEDIUM),
    UDP_FRAGMENT_SKEW(StrategyFamily.UDP, 4, 4, StrategyGroup.EXTREME),
    UDP_GHOST_SKEW(StrategyFamily.UDP, 3, 3, StrategyGroup.HEAVY),
    TLS_SNI_SYMMETRIC_SPLIT(StrategyFamily.TLS, 3, 2, StrategyGroup.MEDIUM),
    TLS_HANDSHAKE_RANDOM_PADDING(StrategyFamily.TLS, 4, 2, StrategyGroup.HEAVY),
    TCP_TOS_MANGLE(StrategyFamily.TCP, 2, 1, StrategyGroup.LIGHT),
    TLS_GREASE_SKEW(StrategyFamily.TLS, 3, 2, StrategyGroup.MEDIUM),
    TLS_CLIENT_HELLO_PAD(StrategyFamily.TLS, 3, 1, StrategyGroup.MEDIUM),
    PROTOCOL_CONFUSION_SSH(StrategyFamily.TCP, 3, 2, StrategyGroup.MEDIUM),
    PROTOCOL_CONFUSION_BITTORRENT(StrategyFamily.TCP, 3, 2, StrategyGroup.MEDIUM),
    PROTOCOL_CONFUSION_REDIS(StrategyFamily.TCP, 3, 2, StrategyGroup.MEDIUM),
    PROTOCOL_CONFUSION_MEMCACHED(StrategyFamily.TCP, 3, 2, StrategyGroup.MEDIUM),
    WS_HANDSHAKE_FAKE(StrategyFamily.HTTP, 3, 3, StrategyGroup.MEDIUM),
    SSH_HANDSHAKE_FAKE(StrategyFamily.TCP, 3, 3, StrategyGroup.MEDIUM),
    HTTP2_PREAMBLE_FAKE(StrategyFamily.HTTP, 3, 3, StrategyGroup.MEDIUM),
    TLS_0RTT_FAKE(StrategyFamily.TLS, 4, 3, StrategyGroup.HEAVY),
    TCP_DATA_OOB_SKEW(StrategyFamily.TCP, 3, 2, StrategyGroup.MEDIUM),
    TCP_SACK_FAKE(StrategyFamily.TCP, 3, 3, StrategyGroup.HEAVY),
    HTTP_HOST_REORDER(StrategyFamily.HTTP, 2, 3, StrategyGroup.MEDIUM),
    HTTP_KEEP_ALIVE_FAKE(StrategyFamily.HTTP, 2, 2, StrategyGroup.LIGHT),
    TLS_CLIENT_HELLO_REORDER(StrategyFamily.TLS, 4, 3, StrategyGroup.EXTREME),
    TLS_ECH_FAKE(StrategyFamily.TLS, 3, 3, StrategyGroup.HEAVY),
    TCP_SEGMENT_DESYNC(StrategyFamily.TCP, 4, 3, StrategyGroup.HEAVY),
    TCP_ACK_SKEW(StrategyFamily.TCP, 2, 2, StrategyGroup.MEDIUM),
    HTTP_METHOD_CASE_MANGLE(StrategyFamily.HTTP, 2, 2, StrategyGroup.MEDIUM),
    TCP_ZERO_WINDOW_DESYNC(StrategyFamily.TCP, 4, 3, StrategyGroup.HEAVY),
    TCP_WINDOW_SIZE_CHAOS(StrategyFamily.TCP, 2, 2, StrategyGroup.MEDIUM),
    TLS_REC_CHOP(StrategyFamily.TLS, 4, 3, StrategyGroup.HEAVY),
    UDP_QUIC_PAD(StrategyFamily.UDP, 2, 2, StrategyGroup.LIGHT),
    TLS_SNI_GREASE(StrategyFamily.TLS, 3, 2, StrategyGroup.MEDIUM),
    BYEBYEDPI_SIM(StrategyFamily.ADAPTIVE, 5, 4, StrategyGroup.EXTREME),
    TCP_OOB_SEGMENTATION(StrategyFamily.TCP, 5, 4, StrategyGroup.HEAVY),
    TCP_OVERLAP(StrategyFamily.TCP, 5, 5, StrategyGroup.EXTREME),
    TCP_WINDOW_SHAKE(StrategyFamily.TCP, 3, 2, StrategyGroup.MEDIUM),
    QUIC_VERSION_SKEW(StrategyFamily.QUIC, 3, 3, StrategyGroup.HEAVY),
    UDP_HEARTBEAT(StrategyFamily.UDP, 2, 1, StrategyGroup.LIGHT),
    TLS_SNI_REVERSE(StrategyFamily.TLS, 4, 3, StrategyGroup.HEAVY),
    TCP_OVERLAP_SKEW(StrategyFamily.TCP, 4, 4, StrategyGroup.EXTREME),
    QUIC_INITIAL_FRAGMENT(StrategyFamily.QUIC, 4, 3, StrategyGroup.HEAVY),
    TLS_SNI_OVERLAP_SKEW(StrategyFamily.TLS, 5, 5, StrategyGroup.EXTREME),
    HTTP_METHOD_SPACE_MANGLE(StrategyFamily.HTTP, 2, 2, StrategyGroup.MEDIUM),
    HTTP_HOST_DOT_MANGLE(StrategyFamily.HTTP, 2, 2, StrategyGroup.MEDIUM),
    TCP_WINDOW_RESIZE_PACING(StrategyFamily.TCP, 3, 3, StrategyGroup.MEDIUM),
    TCP_KEEPALIVE_SKEW(StrategyFamily.TCP, 3, 2, StrategyGroup.MEDIUM),
    TCP_URGENT_DESYNC(StrategyFamily.TCP, 4, 3, StrategyGroup.HEAVY),
    TCP_SYN_FLOOD_FAKE(StrategyFamily.TCP, 4, 3, StrategyGroup.HEAVY),
    TLS_CLIENT_HELLO_MULTI_PAD(StrategyFamily.TLS, 3, 2, StrategyGroup.MEDIUM),
    HTTP_HEADER_CASE_CHAOS(StrategyFamily.HTTP, 3, 2, StrategyGroup.MEDIUM),
    QUIC_HANDSHAKE_SKEW(StrategyFamily.QUIC, 4, 3, StrategyGroup.HEAVY),
    TCP_DATA_DESYNC(StrategyFamily.TCP, 5, 5, StrategyGroup.EXTREME),
    TCP_ACK_SKEW_ADVANCED(StrategyFamily.TCP, 3, 3, StrategyGroup.HEAVY),
    BYEBYEDPI_HYBRID(StrategyFamily.ADAPTIVE, 6, 5, StrategyGroup.EXTREME),
    BYEBYEDPI_EXTREME(StrategyFamily.ADAPTIVE, 6, 5, StrategyGroup.EXTREME),
    ZAPRET_EXTREME(StrategyFamily.ADAPTIVE, 6, 5, StrategyGroup.EXTREME),
    UDP_QUIC_SMART_SHADOW(StrategyFamily.QUIC, 4, 3, StrategyGroup.HEAVY),
    UDP_DNS_REORDER_HYBRID(StrategyFamily.DNS, 3, 2, StrategyGroup.MEDIUM),
    UDP_REORDER(StrategyFamily.UDP, 4, 3, StrategyGroup.HEAVY),
    UDP_SKEW_ADVANCED(StrategyFamily.UDP, 4, 4, StrategyGroup.EXTREME),
    DNS_OVER_TCP_FORCE(StrategyFamily.DNS, 2, 1, StrategyGroup.LIGHT),
    UDP_IP_ID_MANGLE(StrategyFamily.UDP, 3, 2, StrategyGroup.MEDIUM),
    TCP_FOOL_DPI(StrategyFamily.TCP, 4, 3, StrategyGroup.HEAVY),
    TCP_BYTE_FRAG(StrategyFamily.FRAGMENTATION, 5, 4, StrategyGroup.EXTREME),
    TCP_REVERSE_FRAG(StrategyFamily.TCP, 5, 4, StrategyGroup.HEAVY),
    TCP_DATA_DESYNC_OVERLAP(StrategyFamily.TCP, 6, 5, StrategyGroup.EXTREME),
    TCP_FRAGMENT_REORDER(StrategyFamily.TCP, 8, 5, StrategyGroup.EXTREME),
    UDP_SKEW_REVERSE(StrategyFamily.UDP, 4, 3, StrategyGroup.HEAVY),
    TCP_RETRANS_FAKE(StrategyFamily.TCP, 5, 4, StrategyGroup.HEAVY),
    TCP_WINDOW_SIZE_JITTER(StrategyFamily.TCP, 3, 2, StrategyGroup.MEDIUM),
    TLS_SNI_JITTER_SPLIT(StrategyFamily.TLS, 5, 4, StrategyGroup.EXTREME),
    UDP_QUIC_JITTER_PAD(StrategyFamily.UDP, 3, 2, StrategyGroup.MEDIUM),
    TLS_SNI_FRAGMENT(StrategyFamily.FRAGMENTATION, 4, 3, StrategyGroup.HEAVY),
    TCP_TLS_SESSION_DESYNC(StrategyFamily.TCP, 5, 4, StrategyGroup.EXTREME),
    TCP_WINDOW_SIZE_OSCILLATION(StrategyFamily.TCP, 3, 2, StrategyGroup.MEDIUM),
    TCP_SACK_PANIC(StrategyFamily.TCP, 6, 5, StrategyGroup.EXTREME),
    TCP_SACK_SKEW(StrategyFamily.TCP, 5, 4, StrategyGroup.HEAVY),
    TLS_SNI_SKEW_ADVANCED(StrategyFamily.TLS, 6, 6, StrategyGroup.EXTREME),
    TLS_EXT_CHAOS(StrategyFamily.TLS, 5, 5, StrategyGroup.HEAVY),
    HTTP_HEADER_MANGLE(StrategyFamily.HTTP, 2, 1, StrategyGroup.LIGHT),
    HTTP_LINE_SPLIT(StrategyFamily.HTTP, 3, 2, StrategyGroup.MEDIUM),
    HTTP_HOST_REVERSE(StrategyFamily.HTTP, 4, 3, StrategyGroup.HEAVY),
    TCP_TRIPLE_DESYNC(StrategyFamily.TCP, 6, 5, StrategyGroup.EXTREME),
    TCP_FAKE_FIN(StrategyFamily.TCP, 4, 3, StrategyGroup.HEAVY),
    UDP_BURST_CHAOS(StrategyFamily.UDP, 5, 4, StrategyGroup.EXTREME),
    UDP_REPLICATION(StrategyFamily.UDP, 3, 3, StrategyGroup.HEAVY),
    UDP_STUTTER(StrategyFamily.UDP, 2, 2, StrategyGroup.LIGHT),
    UDP_PADDING_CHAOS(StrategyFamily.UDP, 5, 5, StrategyGroup.HEAVY),
    CHAOS(StrategyFamily.ADAPTIVE, 9, 9, StrategyGroup.EXTREME),
    TCP_WINDOW_SHRINK(StrategyFamily.TCP, 4, 3, StrategyGroup.HEAVY),
    TCP_WINDOW_STALL(StrategyFamily.TCP, 4, 3, StrategyGroup.HEAVY),
    TCP_ZERO_WINDOW_OOB(StrategyFamily.TCP, 5, 4, StrategyGroup.EXTREME),
    TCP_TIMING_CHAOS(StrategyFamily.TCP, 4, 3, StrategyGroup.MEDIUM),
    TCP_TLS_HELLO_FRAGMENT(StrategyFamily.TCP, 5, 4, StrategyGroup.HEAVY),
    TCP_TLS_SNI_CASE_MOD(StrategyFamily.TCP, 4, 3, StrategyGroup.MEDIUM),
    UDP_OVERLAP_SKEW(StrategyFamily.UDP, 5, 4, StrategyGroup.HEAVY),
    TCP_REORDER(StrategyFamily.TCP, 4, 3, StrategyGroup.MEDIUM),
    TCP_COMBINED_HYBRID(StrategyFamily.ADAPTIVE, 10, 8, StrategyGroup.EXTREME),
    UDP_COMBINED_HYBRID(StrategyFamily.ADAPTIVE, 8, 7, StrategyGroup.EXTREME),
    TCP_COMBINED_NUCLEAR(StrategyFamily.ADAPTIVE, 12, 10, StrategyGroup.EXTREME),
    UDP_COMBINED_NUCLEAR(StrategyFamily.ADAPTIVE, 12, 10, StrategyGroup.EXTREME),
    ECH_GREASE(StrategyFamily.TLS, 4, 3, StrategyGroup.HEAVY),
    TCP_SEGMENT_OVERLAP(StrategyFamily.TCP, 5, 4, StrategyGroup.EXTREME),
    UDP_QUIC_CHAOS(StrategyFamily.QUIC, 6, 5, StrategyGroup.EXTREME),
    TCP_SEGMENT_REVERSE(StrategyFamily.TCP, 5, 4, StrategyGroup.EXTREME),
    DNS_OVER_QUIC(StrategyFamily.DNS, 4, 3, StrategyGroup.HEAVY),
    DIRECT(StrategyFamily.DIRECT, 0, 0, StrategyGroup.LIGHT)
}

enum class NetworkType { WIFI, MOBILE, UNKNOWN }

enum class HostCategory { STREAMING, SOCIAL, MESSENGER, SEARCH, AI, FINANCE, CDN, NEWS, GAMING, SHOPPING, DEV, AD, GOVERNMENT, SECURITY, OTHER }

enum class DpiType {
    NONE,
    TCP_RESET,
    UDP_BLOCK,
    TLS_SNI_BLOCK,
    DNS_POISONING,
    CONNECTION_TIMEOUT,
    HTTP_BLOCK,
    TLS_HANDSHAKE_TIMEOUT,
    BLACKHOLE,
    TCP_STALL,
    SSL_STALL,
    DNS_VERIFICATION_FAILURE,
    MTU_EXCEEDED
}

data class DpiEvent(val type: DpiType, val timestamp: Long = System.currentTimeMillis())

object ProxyStats {
    private val _dpiEventHistory = MutableStateFlow(emptyList<DpiEvent>())
    val dpiEventHistory: StateFlow<List<DpiEvent>> = _dpiEventHistory.asStateFlow()

    private val _currentDpiType = MutableStateFlow(DpiType.NONE)
    val currentDpiType: StateFlow<DpiType> = _currentDpiType.asStateFlow()

    fun recordDpiEvent(type: DpiType) {
        _currentDpiType.value = type
        _dpiEventHistory.update { current ->
            (current + DpiEvent(type)).takeLast(50)
        }
        dpiEvents[type] = (dpiEvents[type] ?: 0) + 1
        VpnRuntimeState.updateDpi(type.name)
        recordCensorshipEvent(true)
        DpiEngine.recordEvent(type)
        logRecovery("Detected censorship type: $type")
    }
    
    val dpiEvents = ConcurrentHashMap<DpiType, Int>()
    fun resetDpiEvent(type: DpiType) { dpiEvents[type] = 0 }
    
    fun recordDnsFailure() {
        _dnsFailureCount.update { it + 1 }
        recordCensorshipEvent(true)
        DpiEngine.recordEvent(DpiType.DNS_POISONING)
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

    private val bufferPool8k = java.util.concurrent.ConcurrentLinkedQueue<ByteArray>()
    private val bufferPool16k = java.util.concurrent.ConcurrentLinkedQueue<ByteArray>()
    private val bufferPool64k = java.util.concurrent.ConcurrentLinkedQueue<ByteArray>()

    fun obtain8k(): ByteArray {
        return bufferPool8k.poll() ?: ByteArray(8192)
    }

    fun release8k(buf: ByteArray) {
        if (buf.size >= 8192 && bufferPool8k.size < 512) {
            bufferPool8k.offer(buf)
        }
    }

    fun obtain16k(): ByteArray {
        return bufferPool16k.poll() ?: ByteArray(16384)
    }

    fun release16k(buf: ByteArray) {
        if (buf.size >= 16384 && bufferPool16k.size < 256) {
            bufferPool16k.offer(buf)
        }
    }

    fun obtain64k(): ByteArray {
        return bufferPool64k.poll() ?: ByteArray(65536)
    }

    fun release64k(buf: ByteArray) {
        if (buf.size >= 65536 && bufferPool64k.size < 64) {
            bufferPool64k.offer(buf)
        }
    }

    fun releasePool(buf: ByteArray) {
        when (buf.size) {
            8192 -> release8k(buf)
            16384 -> release16k(buf)
            65536 -> release64k(buf)
        }
    }

    fun releaseAllPools() {
        bufferPool8k.clear()
        bufferPool16k.clear()
        bufferPool64k.clear()
    }

    private val strategySuccessMap = java.util.concurrent.ConcurrentHashMap<BypassStrategy, Int>()
    private val strategyFailureMap = java.util.concurrent.ConcurrentHashMap<BypassStrategy, Int>()

    fun reportStrategyResult(strategy: BypassStrategy, success: Boolean) {
        if (success) {
            val current = strategySuccessMap.get(strategy) ?: 0
            strategySuccessMap[strategy] = current + 1
            // Постепенно снижаем счетчик ошибок при успехах
            val fails = strategyFailureMap.get(strategy) ?: 0
            if (fails > 0) strategyFailureMap[strategy] = fails - 1
        } else {
            val current = strategyFailureMap.get(strategy) ?: 0
            strategyFailureMap[strategy] = current + 1
        }
    }

    fun getStrategyScore(strategy: BypassStrategy): Int {
        val success = strategySuccessMap.get(strategy) ?: 0
        val failure = strategyFailureMap.get(strategy) ?: 0
        return success - (failure * 2) // Ошибки наказываются сильнее
    }

    fun resetScores() {
        strategySuccessMap.clear()
        strategyFailureMap.clear()
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

    fun updateCensorshipIntensity(newVal: Int) {
        _censorshipIntensity.value = newVal.coerceIn(0, 100)
    }

    fun clearCensorshipHistory() {
        _censorshipIntensity.value = 0
    }

    fun recordCensorshipEvent(isFailure: Boolean) {
        if (isFailure) {
            _errors.update { it + 1 }
            _successRate.update { (it * 0.85 + 0).toInt().coerceIn(0, 100) }
            _censorshipIntensity.update { (it + 8).coerceAtMost(100) }
        } else {
            _successRate.update { (it * 0.98 + 2).toInt().coerceIn(0, 100) }
            _censorshipIntensity.update { (it - 2).coerceAtLeast(0) }
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

    fun updateStabilityScore(newVal: Int) {
        _stabilityScore.value = newVal.coerceIn(0, 100)
    }

    fun updateCongestionWindow(delta: Int) {
        _congestionWindow.update { (it + delta).coerceIn(1, 1000) }
    }

    private val _maxMss = MutableStateFlow(1460)
    val maxMss: StateFlow<Int> = _maxMss.asStateFlow()

    fun updateMaxMss(newMss: Int) {
        _maxMss.value = newMss
    }

    private val _mssFailureCount = MutableStateFlow(0)
    val mssFailureCount: StateFlow<Int> = _mssFailureCount.asStateFlow()
    
    fun recordMssFailure() {
        _mssFailureCount.update { current ->
            val newVal = current + 1
            logRecovery("MTU auto-correction: incrementing MSS failure count to $newVal")
            if (newVal >= 3) {
                val currentMss = _maxMss.value
                if (currentMss > 512) {
                    val nextMss = (currentMss - 128).coerceAtLeast(512)
                    _maxMss.value = nextMss
                    logRecovery("MTU auto-correction: Reducing Max MSS to $nextMss")
                    0
                } else {
                    newVal
                }
            } else {
                newVal
            }
        }
    }
    
    fun resetMssFailureCount() {
        _mssFailureCount.value = 0
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

                // Automated Recovery/Panic Trigger
                if (successRate.value < 40 && ProxyStats.activeConnections.value > 0) {
                    if (!BypassConfig.isPanicModeFlow.value) {
                        logRecovery("Critical success rate drop (${successRate.value}%). Activating Panic Mode.")
                        BypassConfig.setPanicMode(true)
                    }
                } else if (successRate.value > 85 && BypassConfig.isPanicModeFlow.value) {
                    logRecovery("Stability restored (${successRate.value}%). Deactivating Panic Mode.")
                    BypassConfig.setPanicMode(false)
                }
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
             val jitterPenalty = (jitter / 10).coerceAtMost(30)
             _stabilityScore.update { (it * 0.95 + (100 - jitterPenalty) * 0.05).toInt().coerceIn(0, 100) }
             updateLatency(rtt)
        }
        _censorshipIntensity.update { (it - 3).coerceAtLeast(0) }
        _successRate.update { (it * 0.97 + 3).toInt().coerceIn(0, 100) }
    }

    fun recordGlobalFailure() {
        _censorshipIntensity.update { (it + 5).coerceAtMost(100) }
        _successRate.update { (it * 0.98).toInt().coerceIn(0, 100) }
        _stabilityScore.update { (it - 3).coerceAtLeast(0) }
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
        _activeConnections.update { (it + delta).coerceAtLeast(0) }
    }

    fun getSuccessRate() = _successRate.value
}

object HostClassifier {
    private val cache = ConcurrentHashMap<String, HostCategory>(256)
    
    fun classify(host: String): HostCategory {
        if (host.isEmpty()) return HostCategory.OTHER
        if (cache.size > 1000) cache.clear() // Simple cache eviction
        
        return cache.getOrPut(host) {
            val h = host.lowercase()
            when {
                h.contains("youtube") || h.contains("netflix") || h.contains("twitch") || h.contains("googlevideo") || h.contains("vimeo") || h.contains("ytimg") || h.contains("ggpht") || h.contains("rutube") || h.contains("vkvideo") || h.contains("movies") || h.contains("stream") -> HostCategory.STREAMING
                h.contains("facebook") || h.contains("instagram") || h.contains("twitter") || h.contains("tiktok") || h.contains("linkedin") || h.contains("reddit") || h.contains("fbcdn") || h.contains("twimg") || h.contains("x.com") || h.contains("vk.com") || h.contains("ok.ru") || h.contains("snapchat") || h.contains("pinterest") -> HostCategory.SOCIAL
                h.contains("whatsapp") || h.contains("telegram") || h.contains("discord") || h.contains("signal.org") || h.contains("slack") || h.contains("viber") || h.contains("skype") || h.contains("t.me") || h.contains("tdesktop") || h.contains("messenger") || h.contains("zoom.us") -> HostCategory.MESSENGER
                h.contains("google") || h.contains("bing") || h.contains("duckduckgo") || h.contains("yahoo") || h.contains("baidu") || h.contains("yandex") || h.contains("ask.com") || h.contains("ecosia") || h.contains("wolframalpha") -> HostCategory.SEARCH
                h.contains("openai") || h.contains("anthropic") || h.contains("mistral") || h.contains("perplexity") || h.contains("gemini") || h.contains("chatgpt") || h.contains("claude") || h.contains("deepseek") || h.contains("cohere") || h.contains("grok") || h.contains("llama") || h.contains("huggingface") -> HostCategory.AI
                h.contains("bank") || h.contains("crypto") || h.contains("binance") || h.contains("paypal") || h.contains("visa") || h.contains("stripe") || h.contains("wallet") || h.contains("coinbase") || h.contains("revolut") || h.contains("tinkoff") || h.contains("sber") || h.contains("p2p") || h.contains("blockchain") || h.contains("metamask") || h.contains("ledger") -> HostCategory.FINANCE
                h.contains("github") || h.contains("gitlab") || h.contains("npm") || h.contains("docker") || h.contains("stackoverflow") || h.contains("jetbrains") || h.contains("android") || h.contains("maven") || h.contains("gradle") || h.contains("kotlin") || h.contains("bitbucket") || h.contains("visualstudio") || h.contains("azure") || h.contains("aws") || h.contains("digitalocean") || h.contains("heroku") -> HostCategory.DEV
                h.contains("cloudflare") || h.contains("akamai") || h.contains("fastly") || h.contains("cloudfront") || h.contains("bunny") || h.contains("gvt1") || h.contains("edge") || h.contains("cdn") || h.contains("unpkg") || h.contains("jsdelivr") -> HostCategory.CDN
                h.contains("steam") || h.contains("epicgames") || h.contains("roblox") || h.contains("playstation") || h.contains("xbox") || h.contains("nintendo") || h.contains("blizzard") || h.contains("ea.com") || h.contains("ubisoft") || h.contains("riotgames") || h.contains("unity") -> HostCategory.GAMING
                h.contains("amazon") || h.contains("ebay") || h.contains("aliexpress") || h.contains("shopify") || h.contains("ozon") || h.contains("wildberries") || h.contains("avito") || h.contains("etsy") || h.contains("walmart") -> HostCategory.SHOPPING
                h.contains("ads.") || h.contains("doubleclick") || h.contains("adservice") || h.contains("analytics") || h.contains("telemetry") || h.contains("metrics") || h.contains("crashlytics") || h.contains("segment") || h.contains("mixpanel") -> HostCategory.AD
                h.contains("bbc") || h.contains("cnn") || h.contains("reuters") || h.contains("bloomberg") || h.contains("nytimes") || h.contains("dw.com") || h.contains("rferl") || h.contains("aljazeera") || h.contains("guardian") || h.contains("forbes") -> HostCategory.NEWS
                h.contains("gov") || h.contains("mil") || h.contains("gosuslugi") || h.contains("fsb") || h.contains("mvd") || h.contains("police") -> HostCategory.GOVERNMENT
                h.contains("vpn") || h.contains("proxy") || h.contains("torproject") || h.contains("i2p") || h.contains("shadowsocks") || h.contains("v2ray") || h.contains("wireguard") || h.contains("openvpn") -> HostCategory.SECURITY
                else -> HostCategory.OTHER
            }
        }
    }
}

data class SessionConfig(
    val strategy: BypassStrategy,
    val frag1: Int,
    val delay1: Long,
    val fakeTtl: Int,
    val useIPv6: Boolean = false,
    val frag2: Int = 0,
    val frag3: Int = 0,
    val delay2: Long = 0,
    val mss: Int = 1300
)

data class StrategyMetric(val strategy: BypassStrategy, val score: Int, val successes: Long, val failures: Long, val avgRtt: Long)

enum class StrategyGroup { LIGHT, MEDIUM, HEAVY, EXTREME }

