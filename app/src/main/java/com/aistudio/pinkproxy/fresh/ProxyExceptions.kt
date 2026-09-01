package com.aistudio.pinkproxy.fresh

/**
 * Thrown when DNS resolution fails.
 * Should NOT penalize the bypass strategy, as this is a network/DNS issue.
 */
class DnsException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Thrown when basic transport (TCP/UDP) fails (e.g., No Route to Host, Network Unreachable).
 * Should NOT penalize the bypass strategy heavily, or at all.
 */
class TransportException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Thrown when a DPI bypass strategy fails explicitly (e.g., RST injected by DPI, fragmentation failure).
 * Auto-Tuner SHOULD penalize the strategy for this.
 */
class StrategyException(message: String, val reason: FailureReason, cause: Throwable? = null) : Exception(message, cause)
