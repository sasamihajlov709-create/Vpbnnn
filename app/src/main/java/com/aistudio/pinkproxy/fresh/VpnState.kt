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

    fun updateState(newState: VpnLifecycleState) {
        _lifecycleState.value = newState
    }
}
