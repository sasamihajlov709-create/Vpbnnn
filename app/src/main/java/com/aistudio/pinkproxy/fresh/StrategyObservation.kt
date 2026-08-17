package com.aistudio.pinkproxy.fresh

/**
 * Unified canonical observation record capturing the complete telemetry context of a strategy execution.
 */
data class StrategyObservation(
    val executedStrategy: BypassStrategy,
    val requestedStrategy: BypassStrategy = executedStrategy,
    val effectiveStrategy: BypassStrategy = executedStrategy,
    val transport: TransportType = TransportType.TCP,
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
