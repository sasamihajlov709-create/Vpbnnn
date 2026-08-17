package com.aistudio.pinkproxy.fresh

/**
 * Unified canonical observation record capturing the complete telemetry context of a strategy execution.
 * The transport parameter is strictly mandatory to prevent incorrect inference or protocol leaks.
 */
data class StrategyObservation(
    val executedStrategy: BypassStrategy,
    val transport: TransportType,
    val requestedStrategy: BypassStrategy = executedStrategy,
    val effectiveStrategy: BypassStrategy = executedStrategy,
    val category: HostCategory = HostCategory.OTHER,
    val host: String? = null,
    val profileId: String = "default",
    val success: Boolean,
    val quality: ObservationQuality = if (success) ObservationQuality.APPLICATION_DATA_EXCHANGED else ObservationQuality.CONNECT_ONLY,
    val latencyMs: Long = 0L,
    val failureReason: FailureReason? = null,
    val bytesTransferred: Long = 0L,
    val timestamp: Long = System.currentTimeMillis()
)
