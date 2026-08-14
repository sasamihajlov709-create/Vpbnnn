package com.aistudio.pinkproxy.fresh

/**
 * StrategyExecutorDoq handles DNS-over-QUIC bypass strategies.
 */
object StrategyExecutorDoq : StrategyExecutor {
    override val executorType: StrategyExecutionRegistry.ExecutorType = StrategyExecutionRegistry.ExecutorType.DNS_OVER_QUIC
    override val supportedTransports: Set<TransportType> = setOf(TransportType.DNS, TransportType.UDP)

    override fun supportsStrategy(strategy: BypassStrategy): Boolean {
        return strategy == BypassStrategy.DNS_OVER_QUIC
    }
}
