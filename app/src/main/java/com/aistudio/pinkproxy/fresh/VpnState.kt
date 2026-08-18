package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class VpnLifecycleState {
    IDLE,
    PERMISSION_PENDING,
    STARTING,
    PROBING,
    RUNNING,
    DEGRADED,
    STOPPING,
    FAILED,
    RECOVERING,
    ERROR
}

object VpnRuntimeState {
    private val _lifecycleState = MutableStateFlow(VpnLifecycleState.IDLE)
    val lifecycleState: StateFlow<VpnLifecycleState> = _lifecycleState.asStateFlow()

    private val _lastError = MutableStateFlow<String?>(null)
    val lastError: StateFlow<String?> = _lastError.asStateFlow()

    private val _currentStrategy = MutableStateFlow("Direct")
    val currentStrategy: StateFlow<String> = _currentStrategy.asStateFlow()

    private val _detectedDpi = MutableStateFlow("None")
    val detectedDpi: StateFlow<String> = _detectedDpi.asStateFlow()

    private val _strategySelectionReasoning = MutableStateFlow("Optimal choice for network")
    val strategySelectionReasoning: StateFlow<String> = _strategySelectionReasoning.asStateFlow()

    fun updateState(newState: VpnLifecycleState, error: String? = null) {
        if (error != null) _lastError.value = error
        _lifecycleState.value = newState
    }

    fun clearError() {
        _lastError.value = null
    }

    fun updateStrategy(strategy: String, reason: String? = null) {
        _currentStrategy.value = strategy
        if (reason != null) _strategySelectionReasoning.value = reason
    }

    fun updateDpi(dpi: String) {
        _detectedDpi.value = dpi
    }
}
