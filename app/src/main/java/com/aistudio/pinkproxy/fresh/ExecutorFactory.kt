package com.aistudio.pinkproxy.fresh

object ExecutorFactory {
    private val executorsByType: Map<StrategyExecutionRegistry.ExecutorType, StrategyExecutor> = mapOf(
        StrategyExecutionRegistry.ExecutorType.DIRECT to StrategyExecutorDirect,
        StrategyExecutionRegistry.ExecutorType.TLS_HANDLER to TlsStrategyHandler,
        StrategyExecutionRegistry.ExecutorType.HTTP_HANDLER to HttpStrategyHandler,
        StrategyExecutionRegistry.ExecutorType.TCP_BASIC_HANDLER to TcpBasicStrategyHandler,
        StrategyExecutionRegistry.ExecutorType.FRAGMENTATION_HANDLER to FragmentationStrategyHandler,
        StrategyExecutionRegistry.ExecutorType.ADAPTIVE_HANDLER to AdaptiveStrategyHandler,
        StrategyExecutionRegistry.ExecutorType.TIMING_HANDLER to TimingStrategyHandler,
        StrategyExecutionRegistry.ExecutorType.UDP_HANDLER to UdpStrategyHandler,
        StrategyExecutionRegistry.ExecutorType.DNS_OVER_TCP to StrategyExecutorDns
    )

    fun getExecutor(type: StrategyExecutionRegistry.ExecutorType): StrategyExecutor {
        return executorsByType[type] ?: throw UnsupportedOperationException("No executor instance registered for type: $type")
    }
}
