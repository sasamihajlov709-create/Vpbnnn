package com.aistudio.pinkproxy.fresh.cronet

import com.aistudio.pinkproxy.fresh.NetworkProfileManager
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Isolated metrics specifically for Cronet HTTP/3 operations.
 * Separate from standard TCP/UDP Bypass strategies.
 * Respects Network/Profile awareness.
 */
object CronetMetrics {
    
    class ProfileStats {
        val cronetAttemptCount = AtomicInteger(0)
        val quicHandshakeSuccessCount = AtomicInteger(0)
        val http3RequestSuccessCount = AtomicInteger(0)
        val requestTimeoutCount = AtomicInteger(0)
        val fallbackToTcpCount = AtomicInteger(0)
        val ewmaLatencyMs = AtomicLong(0L)
    }

    private val profileMap = ConcurrentHashMap<String, ProfileStats>()

    private fun getStats(): ProfileStats {
        val profileId = NetworkProfileManager.currentProfile.value.id
        return profileMap.getOrPut(profileId) { ProfileStats() }
    }

    val cronetAttemptCount: Int get() = getStats().cronetAttemptCount.get()
    val quicHandshakeSuccessCount: Int get() = getStats().quicHandshakeSuccessCount.get()
    val http3RequestSuccessCount: Int get() = getStats().http3RequestSuccessCount.get()
    val requestTimeoutCount: Int get() = getStats().requestTimeoutCount.get()
    val fallbackToTcpCount: Int get() = getStats().fallbackToTcpCount.get()
    val p95LatencyApproxMs: Long get() = getStats().ewmaLatencyMs.get()

    fun recordAttempt() {
        getStats().cronetAttemptCount.incrementAndGet()
    }

    fun recordQuicHandshake() {
        getStats().quicHandshakeSuccessCount.incrementAndGet()
    }

    fun recordSuccess(latencyMs: Long, wasQuic: Boolean) {
        val stats = getStats()
        if (wasQuic) {
            stats.http3RequestSuccessCount.incrementAndGet()
        }
        val current = stats.ewmaLatencyMs.get()
        if (current == 0L) {
            stats.ewmaLatencyMs.set(latencyMs)
        } else {
            // Rough EMA update
            stats.ewmaLatencyMs.set((current * 0.9 + latencyMs * 0.1).toLong())
        }
    }

    fun recordTimeout() {
        getStats().requestTimeoutCount.incrementAndGet()
    }

    fun recordFallbackToTcp() {
        getStats().fallbackToTcpCount.incrementAndGet()
    }

    fun reset() {
        profileMap.clear()
    }
}
