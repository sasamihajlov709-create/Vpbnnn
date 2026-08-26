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
    private var sessionJob: CompletableJob? = null
    private var sessionScope: CoroutineScope? = null

    private val _isEngineActive = MutableStateFlow(false)
    val isEngineActive: StateFlow<Boolean> = _isEngineActive.asStateFlow()

    fun initialize(context: Context): Job {
        _isEngineActive.value = true
        return coordinatorScope.launch {
            stateMutex.withLock {
                if (sessionJob?.isActive == true) {
                    Log.d(TAG, "RuntimeCoordinator already initialized and active.")
                    return@withLock
                }
                sessionJob?.cancel()
                val job = SupervisorJob()
                sessionJob = job
                sessionScope = CoroutineScope(ProxyDispatcher.io + job + ProxyDispatcher.globalHandler)
                _isEngineActive.value = true
                Log.i(TAG, "RuntimeCoordinator session initialized successfully.")
            }
        }
    }

    fun shutdown(context: Context): Job {
        _isEngineActive.value = false
        return coordinatorScope.launch {
            stateMutex.withLock {
                sessionScope?.cancel()
                sessionScope = null
                sessionJob?.cancel()
                sessionJob = null
                _isEngineActive.value = false
                Log.i(TAG, "RuntimeCoordinator shutdown completed and session jobs cancelled.")
            }
        }
    }

    /**
     * Centralized transition to a new global bypass strategy with strict transport context and registry validation.
     */
    fun transitionGlobalStrategy(newStrategy: BypassStrategy, transport: TransportType, reason: String): Job {
        val targetScope = sessionScope ?: coordinatorScope
        return targetScope.launch {
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
            DpiStrategySelector.getDefaultFallback(transport)
        }

        Log.i(TAG, "Transitioning strategy for $transport to $targetStrategy. Reason: $reason")
        BypassConfig.applyInternalStrategy(targetStrategy)
        VpnRuntimeState.updateStrategy(targetStrategy.name, DpiStrategySelector.getSelectionReasoning(targetStrategy))
        return true
    }

    suspend fun rotateGlobalStrategy(
        transport: TransportType,
        reason: String,
        category: HostCategory = HostCategory.OTHER,
        profileId: String = NetworkProfileManager.currentProfile.value.id,
        host: String? = null
    ): BypassStrategy {
        val ctx = CandidateEngine.SelectionContext(transport, profileId, host, category)
        val currentStrategy = BypassConfig.getBestStrategyForHost(host ?: "global", transport)
        val best = CandidateEngine.selectBest(ctx, excludeCurrent = currentStrategy) ?: DpiStrategySelector.getDefaultFallback(transport)
        
        Log.i(TAG, "Rotating strategy for $transport [$category/$profileId] to $best. Reason: $reason")
        BypassConfig.applyInternalStrategy(best)
        VpnRuntimeState.updateStrategy(best.name, DpiStrategySelector.getSelectionReasoning(best))
        ProxyStats.logRecovery("Strategy rotated for $transport ($category): ${best.name} ($reason)")
        return best
    }
    /**
     * Non-suspending dispatch version of strategy rotation.
     */
    fun requestGlobalStrategyRotation(
        transport: TransportType,
        reason: String = "Automated Rotation",
        category: HostCategory = HostCategory.OTHER,
        profileId: String = NetworkProfileManager.currentProfile.value.id,
        host: String? = null
    ): Job {
        val targetScope = sessionScope ?: coordinatorScope
        return targetScope.launch {
            rotateGlobalStrategy(transport, reason, category, profileId, host)
        }
    }

    /**
     * Publishes a diagnostic or recovery event directly to the centralized RecoveryStateMachine.
     */
    fun publishRecoverySignal(signal: RecoverySignal) {
        RecoveryStateMachine.postSignal(signal)
    }
}

