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
 * Acts as the single coordinator for bypass runtime state changes, strategy transitions,
 * network profile switches, and recovery state synchronization.
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
     * Centralized transition to a new global bypass strategy with strict transport context.
     */
    fun transitionGlobalStrategy(newStrategy: BypassStrategy, transport: TransportType, reason: String) {
        coordinatorScope.launch {
            stateMutex.withLock {
                Log.i(TAG, "Transitioning global strategy to $newStrategy for $transport. Reason: $reason")
                BypassConfig.setStrategy(newStrategy)
                VpnRuntimeState.updateStrategy(newStrategy.name, reason)
            }
        }
    }

    /**
     * Publishes a diagnostic or recovery event directly to the centralized RecoveryStateMachine.
     */
    fun publishRecoverySignal(signal: RecoverySignal) {
        RecoveryStateMachine.postSignal(signal)
    }
}
