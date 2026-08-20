package com.aistudio.pinkproxy.fresh

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.sqrt

/**
 * Unified canonical state record for a single bypass strategy within a host category or profile.
 */
data class StrategyState(
    val strategy: BypassStrategy,
    val score: AtomicInteger = AtomicInteger(100),
    val sampleCount: AtomicInteger = AtomicInteger(0),
    val successCount: AtomicInteger = AtomicInteger(0),
    val verifiedSuccessCount: AtomicInteger = AtomicInteger(0),
    val failureCount: AtomicInteger = AtomicInteger(0),
    val weightedSuccess: AtomicLong = AtomicLong(0L),
    val totalLatencyMs: AtomicLong = AtomicLong(0L),
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
            val delta = (obs.quality.weight * 1000).toLong().coerceAtLeast(50L)
            weightedSuccess.addAndGet(delta)
            if (obs.latencyMs > 0) {
                totalLatencyMs.addAndGet(obs.latencyMs)
            }
        } else {
            failureCount.incrementAndGet()
        }
    }

    /**
     * Bayesian Beta-Posterior calculation (Beta distribution conjugate prior).
     * Returns a pair of (posteriorMean, posteriorConfidence).
     */
    fun calculateBetaPosterior(priorAlpha: Double = 1.0, priorBeta: Double = 1.0): Pair<Double, Double> {
        val s = verifiedSuccessCount.get().toDouble() + (weightedSuccess.get() / 1000.0) * 0.2
        val f = failureCount.get().toDouble()
        val alpha = priorAlpha + s
        val beta = priorBeta + f
        val total = alpha + beta

        val mean = alpha / total
        // Variance of Beta distribution = (alpha * beta) / ((alpha + beta)^2 * (alpha + beta + 1))
        val variance = (alpha * beta) / (total * total * (total + 1.0))
        val stdDev = sqrt(variance)
        // Confidence increases as variance decreases (1.0 - 2 * stdDev), bounded in [0.05, 0.99]
        val confidence = (1.0 - (stdDev * 3.0)).coerceIn(0.05, 0.99)
        return Pair(mean, confidence)
    }

    /**
     * Empirical Bayes confidence score from 0.0 (no reliable data) to 1.0 (highly confident).
     */
    fun calculateConfidence(): Double {
        return calculateBetaPosterior().second
    }

    val averageLatencyMs: Long
        get() {
            val s = successCount.get()
            return if (s > 0) totalLatencyMs.get() / s else 0L
        }
}

/**
 * Unified Canonical Repository for all strategy states across categories and profiles.
 */
object StrategyStateRepository {
    private val categoryStates = ConcurrentHashMap<HostCategory, ConcurrentHashMap<BypassStrategy, StrategyState>>().apply {
        HostCategory.entries.forEach { cat ->
            val map = ConcurrentHashMap<BypassStrategy, StrategyState>()
            BypassStrategy.entries.forEach { strat ->
                map[strat] = StrategyState(strategy = strat)
            }
            put(cat, map)
        }
    }

    fun getStrategyState(category: HostCategory, strategy: BypassStrategy): StrategyState {
        return categoryStates.getOrPut(category) {
            ConcurrentHashMap()
        }.getOrPut(strategy) {
            StrategyState(strategy = strategy)
        }
    }

    fun recordObservation(obs: StrategyObservation) {
        val state = getStrategyState(obs.category, obs.executedStrategy)
        state.recordObservation(obs)
    }

    fun getAllStates(category: HostCategory): Map<BypassStrategy, StrategyState> {
        return categoryStates[category] ?: emptyMap()
    }

    fun resetAll() {
        categoryStates.values.forEach { catMap ->
            catMap.values.forEach { state ->
                state.score.set(100)
                state.sampleCount.set(0)
                state.successCount.set(0)
                state.verifiedSuccessCount.set(0)
                state.failureCount.set(0)
                state.weightedSuccess.set(0L)
                state.totalLatencyMs.set(0L)
                state.lastUsedTimestamp.set(0L)
            }
        }
    }
}
