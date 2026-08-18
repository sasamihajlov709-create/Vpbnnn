package com.aistudio.pinkproxy.fresh

import java.util.UUID

/**
 * Immutable, thread-safe transport context encapsulating all data-plane flow metadata.
 * Unifies host, port, transport type, applied DPI bypass strategy, network profile,
 * round-trip latency, and QUIC filtering policies across the entire proxy pipeline.
 */
data class FlowContext(
    val host: String,
    val port: Int,
    val transport: TransportType,
    val strategy: BypassStrategy,
    val networkProfile: NetworkProfile = NetworkProfileManager.currentProfile.value,
    val sessionId: String = UUID.randomUUID().toString(),
    val rttMs: Long = 0L,
    val quicMode: QuicBypassMode = BypassConfig.quicBypassMode.value,
    val category: HostCategory = HostClassifier.classify(host),
    val creationTime: Long = System.currentTimeMillis()
) {
    val isTlsPort: Boolean get() = port == 443 || port == 8443
    val isDnsPort: Boolean get() = port == 53 || port == 853
    val isStreamingCategory: Boolean get() = category == HostCategory.STREAMING
    
    fun withStrategy(newStrategy: BypassStrategy): FlowContext {
        return copy(strategy = newStrategy)
    }

    fun withRtt(newRttMs: Long): FlowContext {
        return copy(rttMs = newRttMs)
    }
}
