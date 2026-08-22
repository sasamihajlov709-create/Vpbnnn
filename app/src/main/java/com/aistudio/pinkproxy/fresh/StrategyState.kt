package com.aistudio.pinkproxy.fresh

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.sqrt

/**
 * Immutable context key uniquely identifying strategy execution state.
 */
data class StrategyContextKey(
    val strategy: BypassStrategy,
    val transport: TransportType,
    val category: HostCategory,
    val profileId: String
)

/**
 * Unified canonical state record for a single bypass strategy within a host category, transport and profile.
 */
data class StrategyState(
    val key: StrategyContextKey,
    val score: AtomicInteger = AtomicInteger(100),
    val sampleCount: AtomicInteger = AtomicInteger(0),
    val successCount: AtomicInteger = AtomicInteger(0),
    val verifiedSuccessCount: AtomicInteger = AtomicInteger(0),
    val failureCount: AtomicInteger = AtomicInteger(0),
    val weightedSuccess: AtomicLong = AtomicLong(0L),
    val ewmaLatencyMs: AtomicLong = AtomicLong(0L),
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

    val averageLatencyMs: Long
        get() = ewmaLatencyMs.get()
}

/**
 * Unified Canonical Repository for all strategy states across categories, transports, and profiles.
 */
object StrategyStateRepository {
    private val contextStates = ConcurrentHashMap<StrategyContextKey, StrategyState>()

    fun getStrategyState(
        strategy: BypassStrategy,
        transport: TransportType,
        category: HostCategory,
        profileId: String
    ): StrategyState {
        val key = StrategyContextKey(strategy, transport, category, profileId)
        return contextStates.getOrPut(key) {
            StrategyState(key = key)
        }
    }

    fun getStrategyState(key: StrategyContextKey): StrategyState {
        return contextStates.getOrPut(key) {
            StrategyState(key = key)
        }
    }

    fun recordObservation(obs: StrategyObservation) {
        val state = getStrategyState(obs.executedStrategy, obs.transport, obs.category, obs.profileId)
        state.recordObservation(obs)
    }

    fun getAllStates(
        transport: TransportType,
        category: HostCategory,
        profileId: String
    ): Map<BypassStrategy, StrategyState> {
        return BypassStrategy.entries.associateWith { strategy ->
            getStrategyState(strategy, transport, category, profileId)
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
            state.lastUsedTimestamp.set(metric.lastUsedTimestamp)
        }
    }

    fun resetAll() {
        contextStates.values.forEach { state ->
            state.score.set(100)
            state.sampleCount.set(0)
            state.successCount.set(0)
            state.verifiedSuccessCount.set(0)
            state.failureCount.set(0)
            state.weightedSuccess.set(0L)
            state.ewmaLatencyMs.set(0L)
            state.lastUsedTimestamp.set(0L)
        }
    }
}
