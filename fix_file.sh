cat << 'INNER_EOF' > tmp_StrategyState.kt
package com.aistudio.pinkproxy.fresh

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.sqrt

data class StrategyObservation(
    val executedStrategy: BypassStrategy,
    val transport: TransportType,
    val category: HostCategory,
    val profileId: String,
    val success: Boolean,
    val quality: ObservationQuality,
    val latencyMs: Long,
    val failureReason: FailureReason?,
    val host: String?,
    val timestamp: Long
)

data class HostStrategyBlacklistKey(
    val host: String,
    val transport: TransportType,
    val profileId: String,
    val strategy: BypassStrategy
)

data class StrategyContextKey(
    val strategy: BypassStrategy,
    val transport: TransportType,
    val category: HostCategory,
    val profileId: String
)

data class NetworkMemory(
    val bestStrategy: BypassStrategy,
    val lastUpdated: Long,
    val confidence: Double
)

data class HostMemory(
    val bestStrategy: BypassStrategy,
    val lastUpdated: Long,
    val successCount: Int,
    val transport: TransportType,
    val profileId: String
)

class StrategyState(
    val successCount: AtomicInteger = AtomicInteger(0),
    val verifiedSuccessCount: AtomicInteger = AtomicInteger(0),
    val failureCount: AtomicInteger = AtomicInteger(0),
    val weightedSuccess: AtomicLong = AtomicLong(0L),
    val ewmaLatencyMs: AtomicLong = AtomicLong(0L),
    private val recentLatencies: LongArray = LongArray(100),
    private var latencyIndex: Int = 0,
    private var latencyCount: Int = 0,
    val lastUsedTimestamp: AtomicLong = AtomicLong(0L)
) {
    fun recordObservation(obs: StrategyObservation) {
        sampleCount.incrementAndGet()
        lastUsedTimestamp.set(obs.timestamp)

        if (obs.success) {
            successCount.incrementAndGet()
            if (obs.quality >= ObservationQuality.HANDSHAKE_COMPLETE) {
                verifiedSuccessCount.incrementAndGet()
            }
            
            val delta = (obs.quality.weight * 1000).toLong().coerceAtLeast(0L)
            weightedSuccess.addAndGet(delta)
            
            if (obs.latencyMs > 0) {
                val currentEwma = ewmaLatencyMs.get()
                if (currentEwma == 0L) {
                    ewmaLatencyMs.set(obs.latencyMs)
                } else {
                    // alpha = 0.2
                    val next = (currentEwma * 0.8 + obs.latencyMs * 0.2).toLong()
                    ewmaLatencyMs.set(next)
                }
                synchronized(recentLatencies) {
                    recentLatencies[latencyIndex] = obs.latencyMs
                    latencyIndex = (latencyIndex + 1) % 100
                    if (latencyCount < 100) latencyCount++
                }
            }
        } else {
            failureCount.incrementAndGet()
        }
    }

    /**
     * Clean Bayesian Beta-Posterior calculation (Beta conjugate prior).
     */
    fun calculateBetaPosterior(priorAlpha: Double = 1.0, priorBeta: Double = 1.0): Pair<Double, Double> {
        val s = (weightedSuccess.get() / 1000.0).coerceAtLeast(0.0)
        val f = failureCount.get().toDouble()
        
        val alpha = priorAlpha + s
        val beta = priorBeta + f
        val total = alpha + beta
        val mean = alpha / total
        
        // Variance of Beta distribution = (alpha * beta) / ((alpha + beta)^2 * (alpha + beta + 1))
        val variance = (alpha * beta) / (total * total * (total + 1.0))
        val stdDev = sqrt(variance)
        
        // Confidence scaling based on standard deviation reduction
        val confidence = (1.0 - (stdDev * 3.16)).coerceIn(0.05, 0.99)
        
        return Pair(mean, confidence)
    }

    fun calculateConfidence(): Double {
        return calculateBetaPosterior().second
    }

    @Synchronized
    fun getP95Latency(): Long {
        synchronized(recentLatencies) {
            if (latencyCount == 0) return 0L
            val copy = LongArray(latencyCount)
            System.arraycopy(recentLatencies, 0, copy, 0, latencyCount)
            copy.sort()
            val p95Index = (latencyCount * 0.95).toInt().coerceAtMost(latencyCount - 1)
            return copy[p95Index]
        }
    }

    val averageLatencyMs: Long
        get() = ewmaLatencyMs.get()
        
    val sampleCount: AtomicInteger = AtomicInteger(0)
}

/**
 * Unified Canonical Repository for all strategy states across categories, transports, and profiles.
 */
object StrategyStateRepository {
    private val contextStates = ConcurrentHashMap<StrategyContextKey, StrategyState>()
    val networkStrategyMemory = ConcurrentHashMap<String, ConcurrentHashMap<HostCategory, NetworkMemory>>()
    val contextualHostMemory = ConcurrentHashMap<HostContextKey, HostMemory>()
    val consecutiveFailuresByHost = ConcurrentHashMap<String, AtomicInteger>()
    val hostStrategyBlacklist = ConcurrentHashMap<HostStrategyBlacklistKey, Long>()

    fun recordObservation(obs: StrategyObservation) {
        val state = getStrategyState(obs.executedStrategy, obs.transport, obs.category, obs.profileId)
        state.recordObservation(obs)
    }

    fun getStrategyState(
        strategy: BypassStrategy,
        transport: TransportType,
        category: HostCategory,
        profileId: String
    ): StrategyState {
        val key = StrategyContextKey(strategy, transport, category, profileId)
        return contextStates.getOrPut(key) { StrategyState() }
    }

    fun getStates(
        profileId: String? = null,
        transport: TransportType? = null,
        category: HostCategory? = null,
        strategy: BypassStrategy? = null
    ): List<StrategyState> {
        return contextStates.entries.mapNotNull { (key, state) ->
            if (profileId != null && key.profileId != profileId) return@mapNotNull null
            if (transport != null && key.transport != transport) return@mapNotNull null
            if (category != null && key.category != category) return@mapNotNull null
            if (strategy != null && key.strategy != strategy) return@mapNotNull null
            state
        }
    }

    fun getAllContextStates(): Map<StrategyContextKey, StrategyState> {
        return contextStates.toMap()
    }

    fun restoreStates(states: Map<StrategyContextKey, StrategyMetricState>) {
        states.forEach { (key, metric) ->
            val state = getStrategyState(key.strategy, key.transport, key.category, key.profileId)
            state.score.set(metric.score)
            state.successCount.set(metric.successCount)
            state.failureCount.set(metric.failureCount)
            state.weightedSuccess.set(metric.weightedSuccess)
            state.sampleCount.set(metric.successCount + metric.failureCount)
            state.verifiedSuccessCount.set(metric.verifiedSuccessCount)
            state.ewmaLatencyMs.set(metric.totalLatencyMs)
        }
    }
}
INNER_EOF
mv tmp_StrategyState.kt app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt
