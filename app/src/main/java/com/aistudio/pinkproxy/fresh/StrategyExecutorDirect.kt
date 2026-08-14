package com.aistudio.pinkproxy.fresh

/**
 * StrategyExecutorDirect handles pass-through DIRECT strategy.
 */
object StrategyExecutorDirect : StrategyExecutor {
    override val executorType: StrategyExecutionRegistry.ExecutorType = StrategyExecutionRegistry.ExecutorType.DIRECT
    override val supportedTransports: Set<TransportType> = setOf(TransportType.TCP, TransportType.UDP, TransportType.DNS)

    override fun supportsStrategy(strategy: BypassStrategy): Boolean {
        return strategy == BypassStrategy.DIRECT
    }
}
