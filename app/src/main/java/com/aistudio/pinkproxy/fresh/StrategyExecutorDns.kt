package com.aistudio.pinkproxy.fresh

/**
 * StrategyExecutorDns handles DNS-specific bypass strategies (DNS over TCP / DoQ routing).
 */
object StrategyExecutorDns : StrategyExecutor {
    override val executorType: StrategyExecutionRegistry.ExecutorType = StrategyExecutionRegistry.ExecutorType.DNS_OVER_TCP
    override val supportedTransports: Set<TransportType> = setOf(TransportType.DNS, TransportType.TCP)

    override fun supportsStrategy(strategy: BypassStrategy): Boolean {
        return strategy == BypassStrategy.DNS_OVER_TCP ||
               strategy == BypassStrategy.DNS_NOISE ||
               strategy == BypassStrategy.DNS_CASE_MANGLE ||
               strategy == BypassStrategy.DNS_OVER_TCP_FORCE
    }
}
