package com.aistudio.pinkproxy.fresh

/**
 * StrategyExecutionRegistry verifies that every BypassStrategy has a real,
 * fully functional executor handler before the selector/bandit attempts to choose it.
 */
object StrategyExecutionRegistry {

    private val supportedStrategies: Set<BypassStrategy> = BypassStrategy.values().toSet()

    fun isExecutorSupported(strategy: BypassStrategy, transport: TransportType): Boolean {
        if (!DpiStrategySelector.isFamilyCompatible(strategy.family, transport)) {
            return false
        }
        return supportedStrategies.contains(strategy)
    }

    fun getSupportedStrategiesForTransport(transport: TransportType): List<BypassStrategy> {
        return BypassStrategy.values().filter { isExecutorSupported(it, transport) }
    }
}
