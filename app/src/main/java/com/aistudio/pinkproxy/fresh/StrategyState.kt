package com.aistudio.pinkproxy.fresh

import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Unified canonical state record for a single bypass strategy within a host category or profile.
 */
data class StrategyState(
    val strategy: BypassStrategy,
    val score: AtomicInteger = AtomicInteger(100),
    val sampleCount: AtomicInteger = AtomicInteger(0),
    val successCount: AtomicInteger = AtomicInteger(0),
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
     * Empirical Bayes confidence score from 0.0 (no reliable data) to 1.0 (highly confident).
     */
    fun calculateConfidence(): Double {
        val total = sampleCount.get()
        if (total < 1) return 0.1
        // Smooth asymptotic sigmoid based on sample count and weighted observations
        val sampleFactor = (total / (total + 5.0)).coerceIn(0.1, 1.0)
        val consistencyFactor = if (successCount.get() + failureCount.get() > 0) {
            val s = successCount.get().toDouble()
            val f = failureCount.get().toDouble()
            val winRate = s / (s + f)
            if (winRate > 0.8 || winRate < 0.2) 1.0 else 0.75
        } else 0.5
        return (sampleFactor * consistencyFactor).coerceIn(0.1, 1.0)
    }

    val averageLatencyMs: Long
        get() {
            val s = successCount.get()
            return if (s > 0) totalLatencyMs.get() / s else 0L
        }
}
