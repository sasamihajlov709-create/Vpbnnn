package com.aistudio.pinkproxy.fresh

import android.content.Context
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Unified Control Plane Coordinator.
 * Acts as the single coordinator and owner for bypass runtime state changes, strategy transitions,
 * transport validation, network profile switches, and recovery state synchronization.
 */
object RuntimeCoordinator {
    private const val TAG = "RuntimeCoordinator"

    private val coordinatorScope = CoroutineScope(ProxyDispatcher.io + SupervisorJob() + ProxyDispatcher.globalHandler)
    private val stateMutex = Mutex()

    private val _isEngineActive = MutableStateFlow(false)
    val isEngineActive: StateFlow<Boolean> = _isEngineActive.asStateFlow()

    fun initialize(context: Context) {
        coordinatorScope.launch {
            stateMutex.withLock {
                _isEngineActive.value = true
                Log.i(TAG, "RuntimeCoordinator initialized.")
            }
        }
    }

    fun shutdown(context: Context) {
        coordinatorScope.launch {
            stateMutex.withLock {
                _isEngineActive.value = false
                Log.i(TAG, "RuntimeCoordinator shutdown completed.")
            }
        }
    }

    /**
     * Centralized transition to a new global bypass strategy with strict transport context and registry validation.
     */
    fun transitionGlobalStrategy(newStrategy: BypassStrategy, transport: TransportType, reason: String) {
        coordinatorScope.launch {
            applyStrategyTransition(newStrategy, transport, reason)
        }
    }

    /**
     * Synchronous suspension version of strategy transition for internal engine workflows under mutex.
     */
    suspend fun applyStrategyTransition(newStrategy: BypassStrategy, transport: TransportType, reason: String): Boolean = stateMutex.withLock {
        // Validate transport and registry executor compatibility
        val isFamilyValid = DpiStrategySelector.isFamilyCompatible(newStrategy.family, transport)
        val isExecutorValid = StrategyExecutionRegistry.isExecutorSupported(newStrategy, transport)

        val targetStrategy = if (isFamilyValid && isExecutorValid) {
            newStrategy
        } else {
            val fallback = DpiStrategySelector.getDefaultFallback(transport)
            Log.w(TAG, "Requested strategy $newStrategy is incompatible with $transport (family: $isFamilyValid, executor: $isExecutorValid). Falling back to $fallback")
            fallback
        }

        Log.i(TAG, "Applying global strategy transition to $targetStrategy for $transport. Reason: $reason")
        BypassConfig.applyInternalStrategy(targetStrategy)
        VpnRuntimeState.updateStrategy(targetStrategy.name, reason)
        true
    }

    /**
     * Centralized rotation to the best alternative strategy for a specific transport.
     */
    suspend fun rotateGlobalStrategy(transport: TransportType, reason: String = "Automated Rotation"): BypassStrategy = stateMutex.withLock {
        val current = BypassConfig.strategy.value
        val now = System.currentTimeMillis()
        val candidates = BypassStrategy.entries.filter { 
            it != BypassStrategy.DIRECT && 
            it != current &&
            DpiStrategySelector.isFamilyCompatible(it.family, transport) &&
            StrategyExecutionRegistry.isExecutorSupported(it, transport) &&
            (DpiEngine.circuitBreakers[it] ?: 0L) < now
        }
        val fallback = DpiStrategySelector.getDefaultFallback(transport)
        val best = candidates.maxByOrNull { DpiStrategySelector.getWeightedScore(it, HostCategory.OTHER) } ?: fallback

        Log.i(TAG, "Rotating strategy for $transport to $best. Reason: $reason")
        BypassConfig.applyInternalStrategy(best)
        VpnRuntimeState.updateStrategy(best.name, DpiStrategySelector.getSelectionReasoning(best))
        ProxyStats.logRecovery("Strategy rotated for $transport: ${best.name} ($reason)")
        best
    }

    /**
     * Publishes a diagnostic or recovery event directly to the centralized RecoveryStateMachine.
     */
    fun publishRecoverySignal(signal: RecoverySignal) {
        RecoveryStateMachine.postSignal(signal)
    }
}

