package com.aistudio.pinkproxy.fresh

/**
 * StrategyExecutionRegistry verifies that every BypassStrategy has a real,
 * fully functional executor handler and transport pipeline before the selector/bandit attempts to choose it.
 */
object StrategyExecutionRegistry {

    enum class ExecutorType {
        DIRECT,
        TLS_HANDLER,
        HTTP_HANDLER,
        TCP_BASIC_HANDLER,
        FRAGMENTATION_HANDLER,
        ADAPTIVE_HANDLER,
        TIMING_HANDLER,
        UDP_HANDLER,
        DNS_OVER_TCP,
        DNS_OVER_QUIC
    }

    private val strategyExecutorMap: Map<BypassStrategy, Pair<ExecutorType, Set<TransportType>>> = mapOf(
        // Direct
        BypassStrategy.DIRECT to (ExecutorType.DIRECT to setOf(TransportType.TCP, TransportType.UDP, TransportType.DNS)),

        // TLS Handler (TCP)
        BypassStrategy.SNI_MANGLE to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_DIRTY to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_PAD to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_GREASE to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_EXT_SKEW to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_REC_MANGLE to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_PADDING_RAND to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_REHANDSHAKE_FAKE to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_SNI_SKEW to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_CIPHER_SHUFFLE to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_ALPN_SKEW to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_EXTENSION_GREASE to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_HELLO_JUNK to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_LEGACY_HELLOS to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_SESSION_TICKET_SKEW to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_SESSION_ID_MANGLE to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_MULTI_SNI to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_COMPRESSION_FAKE to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_CHROME_HELLO_FAKE to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_FIREFOX_HELLO_FAKE to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_13_HELLO_FAKE to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_SESSION_ID_RAND to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_MIXED_CASE_SNI to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_SNI_SPLIT to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_CLIENT_HELLO_CHOP to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_APP_DATA_SPLIT to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_CLIENT_HELLO_SHUFFLE to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_RECORD_FRAGMENTATION to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_RECORD_PADDING to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_CLIENT_HELLO_GREASE_RANDOM to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_SNI_NULL_EXT to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_CLIENT_HELLO_PAD_EXTREME to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_EXTENSION_SHUFFLE to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.ECH_FRAG to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_SNI_SYMMETRIC_SPLIT to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_HANDSHAKE_RANDOM_PADDING to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_GREASE_SKEW to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_CLIENT_HELLO_PAD to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_0RTT_FAKE to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_CLIENT_HELLO_REORDER to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_ECH_FAKE to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_REC_CHOP to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_SNI_GREASE to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_SNI_REVERSE to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_SNI_OVERLAP_SKEW to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_CLIENT_HELLO_MULTI_PAD to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_SNI_JITTER_SPLIT to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_SNI_EXT_MANGLE to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_SNI_SKEW_ADVANCED to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_EXT_CHAOS to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.ECH_GREASE to (ExecutorType.TLS_HANDLER to setOf(TransportType.TCP)),

        // HTTP Handler (TCP)
        BypassStrategy.HTTP_HOST_SPACE to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_RANGE_SKEW to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_VERSION_SKEW to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_USER_AGENT_SKEW to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_AUTH_RANDOM to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_HEADER_FUZZING to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_METHOD_FAKE to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_HOST_CASE_MANGLE to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_CHUNKED_FAKE to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_PIPELINE_FAKE to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_HOST_MANGLE to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_FRAGMENT to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_HOST_SMUGGLE to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_HOST_TAB_MANGLE to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_CONNECTION_CLOSE_SKEW to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_MULTI_LINE_MANGLE to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_HOST_FOLDING to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.WS_HANDSHAKE_FAKE to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP2_PREAMBLE_FAKE to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_HOST_REORDER to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_KEEP_ALIVE_FAKE to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_METHOD_CASE_MANGLE to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_METHOD_SPACE_MANGLE to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_HOST_DOT_MANGLE to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_HEADER_CASE_CHAOS to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_HEADER_MANGLE to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_LINE_SPLIT to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.HTTP_HOST_REVERSE to (ExecutorType.HTTP_HANDLER to setOf(TransportType.TCP)),

        // TCP Basic Handler (TCP)
        BypassStrategy.FAKE_PACKET to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_OOB_DESYNC to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.OOB_DESYNC to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.GHOST_PACKETS to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.WINDOW_SIZE_MANGLE to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_ZERO_WINDOW_STALL to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_MSS_CLAMP to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_FAST_RETRANSMIT_SIM to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_REORDER_SIM to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_FAST_OPEN_FAKE to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_RST_FAKE to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_TIMESTAMP_MANGLE to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_URGENT_RANDOM to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_REORDER_CHAOS to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_KEEP_ALIVE_FAKE to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_WINDOW_RESTRICT to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_WINDOW_SCAN to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_REORDER_DESYNC to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_URGENT_SKEW to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_WINDOW_SIZE_SKEW to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_DATA_REPETITION to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_WINDOW_CLAMPING to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_GHOST_SKEW to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.PROTOCOL_CONFUSION_HTTP to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_RANDOM_PADDING to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_MSS_CLUMPING to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_HANDSHAKE_CHAOS to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_MSS_CLAMPER to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_TOS_MANGLE to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.PROTOCOL_CONFUSION_SSH to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.PROTOCOL_CONFUSION_BITTORRENT to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.PROTOCOL_CONFUSION_REDIS to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.PROTOCOL_CONFUSION_MEMCACHED to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.SSH_HANDSHAKE_FAKE to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_DATA_OOB_SKEW to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_SACK_FAKE to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_SEGMENT_DESYNC to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_ACK_SKEW to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_ZERO_WINDOW_DESYNC to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_WINDOW_SIZE_CHAOS to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_OOB_SEGMENTATION to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_OVERLAP to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_WINDOW_SHAKE to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_OVERLAP_SKEW to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_WINDOW_RESIZE_PACING to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_KEEPALIVE_SKEW to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_URGENT_DESYNC to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_SYN_FLOOD_FAKE to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_DATA_DESYNC to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_ACK_SKEW_ADVANCED to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_FOOL_DPI to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_REVERSE_FRAG to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_DATA_DESYNC_OVERLAP to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_FRAGMENT_REORDER to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_RETRANS_FAKE to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_WINDOW_SIZE_JITTER to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_TLS_SESSION_DESYNC to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_WINDOW_SIZE_OSCILLATION to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_SACK_PANIC to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_SACK_SKEW to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_TRIPLE_DESYNC to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_FAKE_FIN to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_WINDOW_SHRINK to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_WINDOW_STALL to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_ZERO_WINDOW_OOB to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_TIMING_CHAOS to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_TLS_HELLO_FRAGMENT to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_TLS_SNI_CASE_MOD to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_REORDER to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_SEGMENT_OVERLAP to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_SEGMENT_REVERSE to (ExecutorType.TCP_BASIC_HANDLER to setOf(TransportType.TCP)),

        // Fragmentation Handler (TCP)
        BypassStrategy.SNI_SPLIT to (ExecutorType.FRAGMENTATION_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.SNI_TRIPLE to (ExecutorType.FRAGMENTATION_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.FRAGMENT_MULTI to (ExecutorType.FRAGMENTATION_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_REC_SPLIT to (ExecutorType.FRAGMENTATION_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_MULTI_FRAG to (ExecutorType.FRAGMENTATION_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_SMALL_CHUNKS to (ExecutorType.FRAGMENTATION_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_REARRANGE_CHUNKS to (ExecutorType.FRAGMENTATION_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_BYTE_FRAG to (ExecutorType.FRAGMENTATION_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TLS_SNI_FRAGMENT to (ExecutorType.FRAGMENTATION_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_PULSE_FRAG to (ExecutorType.FRAGMENTATION_HANDLER to setOf(TransportType.TCP)),

        // Adaptive Handler (TCP & UDP)
        BypassStrategy.ADAPTIVE_CHUNK to (ExecutorType.ADAPTIVE_HANDLER to setOf(TransportType.TCP, TransportType.UDP)),
        BypassStrategy.BYEBYEDPI_SIM to (ExecutorType.ADAPTIVE_HANDLER to setOf(TransportType.TCP, TransportType.UDP)),
        BypassStrategy.BYEBYEDPI_HYBRID to (ExecutorType.ADAPTIVE_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.BYEBYEDPI_EXTREME to (ExecutorType.ADAPTIVE_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.ZAPRET_EXTREME to (ExecutorType.ADAPTIVE_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.CHAOS to (ExecutorType.ADAPTIVE_HANDLER to setOf(TransportType.TCP, TransportType.UDP)),
        BypassStrategy.TCP_COMBINED_HYBRID to (ExecutorType.ADAPTIVE_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.UDP_COMBINED_HYBRID to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.TCP_COMBINED_NUCLEAR to (ExecutorType.ADAPTIVE_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.UDP_COMBINED_NUCLEAR to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),

        // Timing Handler (TCP)
        BypassStrategy.SLOW_SEND to (ExecutorType.TIMING_HANDLER to setOf(TransportType.TCP)),
        BypassStrategy.TCP_ACK_DELAY to (ExecutorType.TIMING_HANDLER to setOf(TransportType.TCP)),

        // UDP Strategy Handler (UDP)
        BypassStrategy.QUIC_RST_SKEW to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.QUIC_MTU_PROBE to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_STUN_FAKE to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_FAKE_DTLS to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_FAKE_SESSION to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_NOISE_PAD to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.QUIC_INITIAL_FAKE to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_WIREGUARD_FAKE to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_IKE_FAKE to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_DHCP_FAKE to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.PROTOCOL_CONFUSION_QUIC to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.PROTOCOL_CONFUSION_DTLS to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_TELEGRAM_FAKE to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_DISCORD_FAKE to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_HIGH_VOL_PACING to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_ZERO_LEN_SKEW to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_NOISE_CHAOS to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_QUIC_SKEW to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_DATA_FRAG to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_FAKE_TRAFFIC to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_IP_FRAG to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.QUIC_INITIAL_PADDING_EXTREME to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.QUIC_INITIAL_FRAGMENTATION to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_IPv6_FRAG to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.QUIC_FORCE_FRAG to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_FRAGMENT_SKEW to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_GHOST_SKEW to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_QUIC_PAD to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.QUIC_VERSION_SKEW to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_HEARTBEAT to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.QUIC_INITIAL_FRAGMENT to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.QUIC_HANDSHAKE_SKEW to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_QUIC_SMART_SHADOW to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_REORDER to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_SKEW_ADVANCED to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_IP_ID_MANGLE to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_SKEW_REVERSE to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_QUIC_JITTER_PAD to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_BURST_CHAOS to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_REPLICATION to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_STUTTER to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_PADDING_CHAOS to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_OVERLAP_SKEW to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_QUIC_CHAOS to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_RACING to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_FAKE_PACKET to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),
        BypassStrategy.UDP_FRAGMENTATION to (ExecutorType.UDP_HANDLER to setOf(TransportType.UDP)),

        // DNS Handlers (Dedicated to TransportType.DNS pipeline)
        BypassStrategy.DNS_OVER_TCP to (ExecutorType.DNS_OVER_TCP to setOf(TransportType.DNS)),
        BypassStrategy.DNS_NOISE to (ExecutorType.DNS_OVER_TCP to setOf(TransportType.DNS)),
        BypassStrategy.DNS_CASE_MANGLE to (ExecutorType.DNS_OVER_TCP to setOf(TransportType.DNS)),
        BypassStrategy.UDP_DNS_REORDER_HYBRID to (ExecutorType.UDP_HANDLER to setOf(TransportType.DNS)),
        BypassStrategy.DNS_OVER_TCP_FORCE to (ExecutorType.DNS_OVER_TCP to setOf(TransportType.DNS)),
        BypassStrategy.DNS_OVER_QUIC to (ExecutorType.DNS_OVER_QUIC to setOf(TransportType.DNS))
    )

    private val executorsByType: Map<ExecutorType, StrategyExecutor> = mapOf(
        ExecutorType.DIRECT to StrategyExecutorDirect,
        ExecutorType.TLS_HANDLER to TlsStrategyHandler,
        ExecutorType.HTTP_HANDLER to HttpStrategyHandler,
        ExecutorType.TCP_BASIC_HANDLER to TcpBasicStrategyHandler,
        ExecutorType.FRAGMENTATION_HANDLER to FragmentationStrategyHandler,
        ExecutorType.ADAPTIVE_HANDLER to AdaptiveStrategyHandler,
        ExecutorType.TIMING_HANDLER to TimingStrategyHandler,
        ExecutorType.UDP_HANDLER to UdpStrategyHandler,
        ExecutorType.DNS_OVER_TCP to StrategyExecutorDns,
        ExecutorType.DNS_OVER_QUIC to StrategyExecutorDoq
    )

    fun getExecutor(strategy: BypassStrategy): StrategyExecutor {
        val type = getExecutorType(strategy) ?: return StrategyExecutorDirect
        return executorsByType[type] ?: StrategyExecutorDirect
    }

    fun getExecutorByType(type: ExecutorType): StrategyExecutor {
        return executorsByType[type] ?: StrategyExecutorDirect
    }

    fun isExecutorSupported(strategy: BypassStrategy, transport: TransportType): Boolean {
        val entry = strategyExecutorMap[strategy] ?: return false
        if (!entry.second.contains(transport)) return false
        val executor = executorsByType[entry.first] ?: return false
        return executor.supportsStrategy(strategy)
    }

    fun getExecutorType(strategy: BypassStrategy): ExecutorType? {
        return strategyExecutorMap[strategy]?.first
    }

    fun isActuallyImplemented(strategy: BypassStrategy): Boolean {
        return strategyExecutorMap.containsKey(strategy)
    }

    fun getSupportedStrategiesForTransport(transport: TransportType): List<BypassStrategy> {
        return BypassStrategy.entries.filter { isExecutorSupported(it, transport) }
    }
}

