package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class VpnLifecycleState {
    IDLE,
    PERMISSION_PENDING,
    STARTING,
    RUNNING,
    STOPPING,
    FAILED,
    RECOVERING
}

object VpnRuntimeState {
    private val _lifecycleState = MutableStateFlow(VpnLifecycleState.IDLE)
    val lifecycleState: StateFlow<VpnLifecycleState> = _lifecycleState.asStateFlow()

    private val _currentStrategy = MutableStateFlow("Direct")
    val currentStrategy: StateFlow<String> = _currentStrategy.asStateFlow()

    private val _detectedDpi = MutableStateFlow("None")
    val detectedDpi: StateFlow<String> = _detectedDpi.asStateFlow()

    fun updateState(newState: VpnLifecycleState) {
        _lifecycleState.value = newState
    }

    fun updateStrategy(strategy: String) {
        _currentStrategy.value = strategy
    }

    fun updateDpi(dpi: String) {
        _detectedDpi.value = dpi
    }
}
