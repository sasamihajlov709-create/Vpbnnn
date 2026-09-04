package com.aistudio.pinkproxy.fresh

import java.util.concurrent.ConcurrentHashMap

/**
 * Intelligent Escalation Matrix for Deep Packet Inspection (DPI) & Censorship Evasion.
 * Dynamically maps failures (TCP Resets, SNI-based silent drops, Handshake corruption, DNS poisoning)
 * to domain-specific, highly resistant bypass escalation chains.
 */
object StrategyEscalationGraph {

    // 1. TCP Reset / Active Injection Escalation Chain (OOB, SEQ Overlap, Fake FIN, Desync, Combined Nuclear)
    val tcpResetChain: List<BypassStrategy> = listOf(
        BypassStrategy.SNI_SPLIT,
        BypassStrategy.TLS_SNI_FRAGMENT,
        BypassStrategy.TCP_SMALL_CHUNKS,
        BypassStrategy.TCP_REARRANGE_CHUNKS,
        BypassStrategy.TCP_DATA_DESYNC_OVERLAP,
        BypassStrategy.OOB_DESYNC,
        BypassStrategy.BYEBYEDPI_HYBRID,
        BypassStrategy.ZAPRET_EXTREME,
        BypassStrategy.TCP_COMBINED_HYBRID,
        BypassStrategy.TCP_COMBINED_NUCLEAR
    )

    // 2. Censorship Stall / Silent Drop Escalation Chain (SNI Jitter, Multi-Split, ByeByeDPI Extreme, Zapret Extreme)
    val censorshipStallChain: List<BypassStrategy> = listOf(
        BypassStrategy.SNI_SPLIT,
        BypassStrategy.TLS_SNI_FRAGMENT,
        BypassStrategy.TLS_SNI_JITTER_SPLIT,
        BypassStrategy.TLS_CLIENT_HELLO_CHOP,
        BypassStrategy.BYEBYEDPI_SIM,
        BypassStrategy.BYEBYEDPI_HYBRID,
        BypassStrategy.BYEBYEDPI_EXTREME,
        BypassStrategy.ZAPRET_EXTREME,
        BypassStrategy.CHAOS,
        BypassStrategy.TCP_COMBINED_NUCLEAR
    )

    // 3. SSL Handshake Error / Record Tampering Escalation Chain
    val sslHandshakeChain: List<BypassStrategy> = listOf(
        BypassStrategy.TLS_PAD,
        BypassStrategy.TLS_GREASE,
        BypassStrategy.TLS_SNI_FRAGMENT,
        BypassStrategy.TLS_APP_DATA_SPLIT,
        BypassStrategy.TLS_REC_SPLIT,
        BypassStrategy.TLS_0RTT_FAKE,
        BypassStrategy.TLS_CLIENT_HELLO_CHOP,
        BypassStrategy.BYEBYEDPI_HYBRID,
        BypassStrategy.ZAPRET_EXTREME,
        BypassStrategy.CHAOS,
        BypassStrategy.TCP_COMBINED_NUCLEAR
    )

    // 4. DNS Poisoning Escalation Chain
    val dnsEscalationChain: List<BypassStrategy> = listOf(
        BypassStrategy.DNS_CASE_MANGLE,
        BypassStrategy.DNS_NOISE,
        BypassStrategy.DNS_OVER_TCP,
        BypassStrategy.DNS_OVER_TCP_FORCE,
        BypassStrategy.DOH_OVER_QUIC
    )

    // 5. UDP / QUIC Disruption Escalation Chain
    val udpDisruptionChain: List<BypassStrategy> = listOf(
        BypassStrategy.UDP_QUIC_PAD,
        BypassStrategy.QUIC_INITIAL_FRAGMENT,
        BypassStrategy.UDP_FRAGMENT_SKEW,
        BypassStrategy.UDP_NOISE_PAD,
        BypassStrategy.UDP_DATA_FRAG,
        BypassStrategy.UDP_QUIC_SMART_SHADOW,
        BypassStrategy.QUIC_INITIAL_FRAGMENTATION,
        BypassStrategy.UDP_NOISE_CHAOS,
        BypassStrategy.UDP_COMBINED_HYBRID,
        BypassStrategy.UDP_COMBINED_NUCLEAR
    )

    // 6. Generic Default Escalation Chain
    val defaultTcpChain: List<BypassStrategy> = listOf(
        BypassStrategy.SNI_SPLIT,
        BypassStrategy.TLS_SNI_FRAGMENT,
        BypassStrategy.TCP_SMALL_CHUNKS,
        BypassStrategy.TLS_APP_DATA_SPLIT,
        BypassStrategy.BYEBYEDPI_HYBRID,
        BypassStrategy.TCP_REARRANGE_CHUNKS,
        BypassStrategy.TCP_DATA_DESYNC_OVERLAP,
        BypassStrategy.OOB_DESYNC,
        BypassStrategy.ZAPRET_EXTREME,
        BypassStrategy.TCP_COMBINED_NUCLEAR
    )

    val strategyChains = ConcurrentHashMap<BypassStrategy, BypassStrategy>()
    
    init {
        // Link default chain
        for (i in 0 until defaultTcpChain.size - 1) {
            strategyChains[defaultTcpChain[i]] = defaultTcpChain[i + 1]
        }

        // Link UDP disruption chain
        for (i in 0 until udpDisruptionChain.size - 1) {
            strategyChains[udpDisruptionChain[i]] = udpDisruptionChain[i + 1]
        }

        // Link DNS escalation chain
        for (i in 0 until dnsEscalationChain.size - 1) {
            strategyChains[dnsEscalationChain[i]] = dnsEscalationChain[i + 1]
        }
        
        // Extra linkages
        strategyChains[BypassStrategy.TCP_FOOL_DPI] = BypassStrategy.ZAPRET_EXTREME
        strategyChains[BypassStrategy.ZAPRET_EXTREME] = BypassStrategy.TCP_COMBINED_NUCLEAR
        strategyChains[BypassStrategy.BYEBYEDPI_EXTREME] = BypassStrategy.TCP_COMBINED_NUCLEAR
        strategyChains[BypassStrategy.CHAOS] = BypassStrategy.TCP_COMBINED_NUCLEAR
        strategyChains[BypassStrategy.UDP_NOISE_CHAOS] = BypassStrategy.UDP_COMBINED_HYBRID
        strategyChains[BypassStrategy.UDP_COMBINED_HYBRID] = BypassStrategy.UDP_COMBINED_NUCLEAR
    }

    /**
     * Resolves the next escalated strategy taking into account the failure reason, transport, and availability.
     */
    fun getEscalatedStrategy(
        failedStrategy: BypassStrategy,
        reason: FailureReason? = null,
        transport: TransportType,
        host: String? = null,
        category: HostCategory? = null
    ): BypassStrategy? {
        val chain = selectChainForContext(reason, transport)
        val index = chain.indexOf(failedStrategy)
        val now = System.currentTimeMillis()
        val profileId = NetworkProfileManager.currentProfile.value.id

        // Check if failed strategy is in the dedicated chain
        val candidates = if (index >= 0 && index < chain.size - 1) {
            chain.subList(index + 1, chain.size)
        } else {
            // If not directly in chain, look at fallback from targetMap or tail of chain
            val nextDirect = StrategyEscalationGraph.strategyChains[failedStrategy]
            if (nextDirect != null) {
                listOf(nextDirect) + chain
            } else {
                chain
            }
        }

        val ctx = CandidateEngine.SelectionContext(transport, profileId, host, category ?: (host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER))
        for (candidate in candidates) {
            if (candidate == failedStrategy) continue
            if (!StrategyPolicyGate.isAllowed(candidate, ctx)) continue
            
            // Check host-specific blacklist
            if (host != null) {
                val blKey = HostStrategyBlacklistKey(host, transport, profileId, candidate)
                val bl = StrategyStateRepository.hostStrategyBlacklist[blKey] ?: 0L
                if (bl >= now) continue
            }

            return candidate
        }

        // Fallback to diverse extreme strategy if all chain members are exhausted or blocked
        val fallback = DpiStrategySelector.getFallbackStrategy(failedStrategy, transport)
        return if (StrategyPolicyGate.isAllowed(fallback, ctx)) fallback else null
    }

    private fun selectChainForContext(reason: FailureReason?, transport: TransportType): List<BypassStrategy> {
        return when (transport) {
            TransportType.UDP -> udpDisruptionChain
            TransportType.DNS -> dnsEscalationChain
            TransportType.TCP -> {
                when (reason) {
                    FailureReason.TCP_RESET, FailureReason.CONNECTION_REFUSED -> tcpResetChain
                    FailureReason.CENSORSHIP_STALL, FailureReason.TIMEOUT -> censorshipStallChain
                    FailureReason.SSL_HANDSHAKE_ERROR, FailureReason.HANDSHAKE_TIMEOUT -> sslHandshakeChain
                    FailureReason.DNS_POISONED -> dnsEscalationChain
                    else -> defaultTcpChain
                }
            }
        }
    }
}
