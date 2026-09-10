package com.aistudio.pinkproxy.fresh

object CapabilityMatrix {

    fun isExecutorSupported(strategy: BypassStrategy, transport: TransportType): Boolean {
        val entry = StrategyExecutionRegistry.getStrategyEntry(strategy) ?: return false
        if (!entry.second.contains(transport)) return false
        val executor = ExecutorFactory.getExecutor(entry.first)
        return executor.supportsStrategy(strategy)
    }

    fun isActuallyImplemented(strategy: BypassStrategy): Boolean {
        return StrategyExecutionRegistry.getStrategyEntry(strategy) != null
    }

    fun getExecutorCompatibleStrategies(transport: TransportType): List<BypassStrategy> {
        return BypassStrategy.entries.filter { isExecutorSupported(it, transport) }
    }
}
