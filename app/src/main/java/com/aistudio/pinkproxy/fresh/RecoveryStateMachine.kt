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
 * State definitions for the centralized recovery engine.
 */
enum class RecoveryState {
    IDLE,
    DEGRADED,
    PROBING,
    RECONFIGURING_MTU,
    PANIC_MODE,
    RESTARTING_PROXY,
    RESTARTING_TUNNEL
}

/**
 * Strongly-typed event signals published by health monitors and network observers.
 */
sealed class RecoverySignal {
    data class DpiDetected(val type: DpiType, val host: String? = null, val transport: TransportType = TransportType.TCP) : RecoverySignal()
    data class TunnelStall(val durationMs: Long, val activeConnections: Int, val transport: TransportType = TransportType.TCP) : RecoverySignal()
    data class TcpStall(val host: String, val strategy: BypassStrategy, val transport: TransportType = TransportType.TCP) : RecoverySignal()
    data class SslStall(val host: String, val strategy: BypassStrategy, val transport: TransportType = TransportType.TCP) : RecoverySignal()
    data class DnsFailure(val domain: String, val isPoisoned: Boolean, val transport: TransportType = TransportType.DNS) : RecoverySignal()
    data class ProxyUnresponsive(val reason: String, val transport: TransportType = TransportType.TCP) : RecoverySignal()
    data class MemoryPressure(val usedPercent: Int) : RecoverySignal()
    data class ExtremeLatency(val latencyMs: Long, val transport: TransportType = TransportType.TCP) : RecoverySignal()
    data class HealthDegraded(val details: String, val transport: TransportType = TransportType.TCP) : RecoverySignal()
    data class NetworkLost(val networkType: String) : RecoverySignal()
    object ManualReset : RecoverySignal()
}

/**
 * RecoveryStateMachine: Single source of truth and decision owner for all recovery operations.
 */
object RecoveryStateMachine {
    private const val TAG = "RecoveryStateMachine"

    private val _currentState = MutableStateFlow(RecoveryState.IDLE)
    val currentState: StateFlow<RecoveryState> = _currentState.asStateFlow()

    private val escalationLevel = java.util.concurrent.atomic.AtomicInteger(0)
    private var lastRestartTimestamp = 0L
    private var restartCooldownMs = 60000L
    private val stateMutex = Mutex()
    private var machineScope: CoroutineScope? = null

    fun start(scope: CoroutineScope) {
        machineScope = scope
        _currentState.value = RecoveryState.IDLE
        escalationLevel.set(0)
        Log.i(TAG, "RecoveryStateMachine initialized in IDLE state")
    }

    fun stop() {
        machineScope = null
        _currentState.value = RecoveryState.IDLE
    }

    /**
     * Dispatch an event to the state machine asynchronously.
     */
    fun postSignal(signal: RecoverySignal) {
        val scope = machineScope ?: PinkVpnService.instance?.getServiceScope() ?: ProxyDispatcher.mainScope
        scope.launch(ProxyDispatcher.io) {
            handleSignal(signal)
        }
    }

    /**
     * Synchronously process recovery signal under stateMutex lock to prevent race conditions.
     */
    suspend fun handleSignal(signal: RecoverySignal) = stateMutex.withLock {
        Log.w(TAG, "Processing signal: $signal (Current State: ${_currentState.value}, Escalation: ${escalationLevel.get()})")
        ProxyStats.logRecovery("Signal: ${signal.javaClass.simpleName}")

        when (signal) {
            is RecoverySignal.DpiDetected -> processDpiSignal(signal)
            is RecoverySignal.TunnelStall -> processTunnelStall(signal.durationMs, signal.activeConnections, signal.transport)
            is RecoverySignal.TcpStall, is RecoverySignal.SslStall -> processSocketStall(signal)
            is RecoverySignal.DnsFailure -> processDnsFailure(signal)
            is RecoverySignal.ProxyUnresponsive -> processProxyUnresponsive(signal.reason, signal.transport)
            is RecoverySignal.MemoryPressure -> processMemoryPressure(signal.usedPercent)
            is RecoverySignal.ExtremeLatency -> processExtremeLatency(signal.latencyMs, signal.transport)
            is RecoverySignal.HealthDegraded -> processHealthDegraded(signal.details, signal.transport)
            is RecoverySignal.NetworkLost -> processNetworkLost(signal.networkType)
            is RecoverySignal.ManualReset -> processManualReset()
        }
    }

    private fun processDpiSignal(signal: RecoverySignal.DpiDetected) {
        _currentState.value = RecoveryState.DEGRADED
        val type = signal.type
        val targetHost = signal.host
        val transport = signal.transport
        when (type) {
            DpiType.TCP_RESET -> {
                val candidates = listOf(
                    BypassStrategy.TCP_COMBINED_NUCLEAR,
                    BypassStrategy.TCP_COMBINED_HYBRID,
                    BypassStrategy.TCP_DATA_DESYNC_OVERLAP,
                    BypassStrategy.OOB_DESYNC
                ).filter { StrategyExecutionRegistry.isExecutorSupported(it, TransportType.TCP) }
                val selected = candidates.maxWithOrNull(
                    compareBy<BypassStrategy> { DpiStrategySelector.getWeightedScore(it, HostCategory.OTHER) }
                        .thenBy { it.name.hashCode() }
                ) ?: BypassStrategy.TCP_COMBINED_NUCLEAR
                BypassConfig.setGlobalStrategy(selected)
                if (targetHost != null) {
                    DpiStrategySelector.escalateHostStrategy(targetHost, selected, FailureReason.TCP_RESET)
                }
                enterPanic("Active TCP Reset DPI detected")
            }
            DpiType.TLS_SNI_BLOCK -> {
                val candidates = listOf(
                    BypassStrategy.TCP_COMBINED_NUCLEAR,
                    BypassStrategy.BYEBYEDPI_EXTREME,
                    BypassStrategy.ZAPRET_EXTREME,
                    BypassStrategy.SNI_SPLIT,
                    BypassStrategy.TLS_CLIENT_HELLO_CHOP
                ).filter { StrategyExecutionRegistry.isExecutorSupported(it, TransportType.TCP) }
                val selected = candidates.maxWithOrNull(
                    compareBy<BypassStrategy> { DpiStrategySelector.getWeightedScore(it, HostCategory.OTHER) }
                        .thenBy { it.name.hashCode() }
                ) ?: BypassStrategy.SNI_SPLIT
                BypassConfig.setGlobalStrategy(selected)
                if (targetHost != null) {
                    DpiStrategySelector.escalateHostStrategy(targetHost, selected, FailureReason.CENSORSHIP_STALL)
                }
            }
            DpiType.HTTP_BLOCK -> {
                val candidates = listOf(
                    BypassStrategy.HTTP_HOST_SPACE,
                    BypassStrategy.HTTP_HOST_CASE_MANGLE,
                    BypassStrategy.HTTP_HOST_TAB_MANGLE,
                    BypassStrategy.HTTP_METHOD_CASE_MANGLE,
                    BypassStrategy.HTTP_HOST_REORDER
                ).filter { StrategyExecutionRegistry.isExecutorSupported(it, TransportType.TCP) }
                val selected = candidates.maxWithOrNull(
                    compareBy<BypassStrategy> { DpiStrategySelector.getWeightedScore(it, HostCategory.OTHER) }
                        .thenBy { it.name.hashCode() }
                ) ?: BypassStrategy.HTTP_HOST_SPACE
                BypassConfig.setGlobalStrategy(selected)
                if (targetHost != null) {
                    DpiStrategySelector.escalateHostStrategy(targetHost, selected, FailureReason.CENSORSHIP_STALL)
                }
            }
            DpiType.CONNECTION_TIMEOUT -> {
                val candidates = listOf(
                    BypassStrategy.TLS_REC_SPLIT, 
                    BypassStrategy.TCP_ACK_SKEW, 
                    BypassStrategy.TCP_WINDOW_SIZE_CHAOS
                ).filter { StrategyExecutionRegistry.isExecutorSupported(it, transport) }
                val selected = candidates.maxWithOrNull(
                    compareBy<BypassStrategy> { DpiStrategySelector.getWeightedScore(it, HostCategory.OTHER) }
                        .thenBy { it.name.hashCode() }
                ) ?: DpiStrategySelector.getDefaultFallback(transport)
                BypassConfig.setGlobalStrategy(selected)
                if (targetHost != null) {
                    DpiStrategySelector.escalateHostStrategy(targetHost, selected, FailureReason.TIMEOUT)
                }
                if (escalationLevel.get() >= 2) enterPanic("DPI Timeout Escalation")
            }
            DpiType.UDP_BLOCK -> {
                val candidates = listOf(
                    BypassStrategy.UDP_COMBINED_NUCLEAR,
                    BypassStrategy.UDP_COMBINED_HYBRID,
                    BypassStrategy.UDP_QUIC_SMART_SHADOW,
                    BypassStrategy.QUIC_INITIAL_FRAGMENTATION
                ).filter { StrategyExecutionRegistry.isExecutorSupported(it, TransportType.UDP) }
                val selected = candidates.maxWithOrNull(
                    compareBy<BypassStrategy> { DpiStrategySelector.getWeightedScore(it, HostCategory.OTHER) }
                        .thenBy { it.name.hashCode() }
                ) ?: BypassStrategy.UDP_COMBINED_NUCLEAR
                BypassConfig.setGlobalStrategy(selected)
                if (targetHost != null) {
                    DpiStrategySelector.escalateHostStrategy(targetHost, selected, FailureReason.TIMEOUT)
                }
            }
            else -> {
                BypassConfig.rotateGlobalStrategy(transport)
            }
        }

        escalationLevel.set((escalationLevel.get() + 1).coerceAtMost(3))
        triggerActiveProbeAsync(3000L)
    }

    private fun processTunnelStall(durationMs: Long, activeConns: Int, transport: TransportType) {
        val currentEsc = escalationLevel.get()
        if (currentEsc < 3) {
            _currentState.value = RecoveryState.RECONFIGURING_MTU
            BypassConfig.rotateGlobalStrategy(transport)

            if (currentEsc > 0) {
                val currentMtu = BypassConfig.currentMtu.value
                if (currentMtu > 1100) {
                    val reduction = 80
                    BypassConfig.setMtu(currentMtu - reduction)
                    ProxyStats.logRecovery("Watchdog: Reducing MTU to ${currentMtu - reduction} due to tunnel stall")
                }

                // Dynamic TTL shifting
                val nextTtl = when (BypassConfig.currentTtl) {
                    3 -> 5
                    5 -> 8
                    8 -> 10
                    else -> 3
                }
                BypassConfig.setTtl(nextTtl)
            }
            escalationLevel.incrementAndGet()
            triggerActiveProbeAsync(2000L)
        } else {
            enterPanic("Critical tunnel stall ($durationMs ms, $activeConns conns)")
            requestTunnelRestart("Persistent tunnel stall")
        }
    }

    private fun processSocketStall(signal: RecoverySignal) {
        _currentState.value = RecoveryState.DEGRADED
        val transport = when (signal) {
            is RecoverySignal.TcpStall -> signal.transport
            is RecoverySignal.SslStall -> signal.transport
            else -> TransportType.TCP
        }
        val candidates = listOf(
            BypassStrategy.TLS_REC_SPLIT,
            BypassStrategy.TLS_CLIENT_HELLO_CHOP,
            BypassStrategy.BYEBYEDPI_EXTREME,
            BypassStrategy.TCP_WINDOW_SHRINK,
            BypassStrategy.TCP_TLS_SESSION_DESYNC
        ).filter { StrategyExecutionRegistry.isExecutorSupported(it, transport) }
        val selected = candidates.maxWithOrNull(
            compareBy<BypassStrategy> { DpiStrategySelector.getWeightedScore(it, HostCategory.OTHER) }
                .thenBy { it.name.hashCode() }
        ) ?: DpiStrategySelector.getDefaultFallback(transport)
        BypassConfig.setGlobalStrategy(selected)

        val currentMtu = BypassConfig.currentMtu.value
        if (currentMtu > 1100) {
            BypassConfig.setMtu(currentMtu - 150)
            ProxyStats.logRecovery("Stall Handler: Reduced MTU to ${currentMtu - 150}")
        }
        escalationLevel.incrementAndGet()
        triggerActiveProbeAsync(2000L)
    }

    private fun processDnsFailure(signal: RecoverySignal.DnsFailure) {
        _currentState.value = RecoveryState.DEGRADED
        RobustResolver.clearCache()
        DnsCacheManager.clearAll()
        DnsOptimizer.forceRefresh()

        if (signal.isPoisoned) {
            enterPanic("DNS Poisoning detected for ${signal.domain}")
            RobustResolver.dnsMode = "Smart DoH"
        }

        if (escalationLevel.get() < 2) {
            escalationLevel.incrementAndGet()
        } else {
            enterPanic("Repeated DNS failures")
            requestTunnelRestart("Persistent DNS failures/poisoning")
        }
    }

    private fun processProxyUnresponsive(reason: String, transport: TransportType) {
        val currentEsc = escalationLevel.get()
        if (currentEsc < 2) {
            _currentState.value = RecoveryState.RESTARTING_PROXY
            escalationLevel.incrementAndGet()
            Log.w(TAG, "Proxy unresponsive ($reason), restarting internal server (escalation ${currentEsc + 1})")
            PinkVpnService.instance?.restartProxyServer()
        } else {
            escalationLevel.set(3)
            enterPanic("Proxy server unreachable")
            requestTunnelRestart("Proxy server crash ($reason)")
        }
    }

    private fun processMemoryPressure(usedPercent: Int) {
        Log.w(TAG, "Handling memory pressure: $usedPercent%")
        DnsCacheManager.clearAll()
        UdpTransportHandler.clearBuffers()
        ProxyStats.releaseAllPools()

        if (usedPercent > 92) {
            _currentState.value = RecoveryState.DEGRADED
            requestTunnelRestart("Emergency memory exhaustion cleanup ($usedPercent%)")
        }
    }

    private fun processExtremeLatency(latencyMs: Long, transport: TransportType) {
        _currentState.value = RecoveryState.DEGRADED
        BypassConfig.rotateGlobalStrategy(transport)
        escalationLevel.set((escalationLevel.get() + 1).coerceAtMost(2))
    }

    private fun processHealthDegraded(details: String, transport: TransportType) {
        _currentState.value = RecoveryState.DEGRADED
        BypassConfig.rotateGlobalStrategy(transport)
    }

    private fun processNetworkLost(networkType: String) {
        Log.i(TAG, "Active network lost ($networkType). Cooling down and re-evaluating routes.")
        _currentState.value = RecoveryState.PROBING
        DnsCacheManager.clearAll()
        RobustResolver.clearCache()
    }

    private fun processManualReset() {
        Log.w(TAG, "Manual full recalibration triggered")
        _currentState.value = RecoveryState.IDLE
        DpiPolicyEngine.resetAllEngineStates()
        DnsCacheManager.clearAll()
        RobustResolver.clearCache()
        DnsOptimizer.forceRefresh()
        escalationLevel.set(0)
        BypassConfig.setPanicMode(false)
        BypassConfig.setMtu(1400)
        triggerActiveProbeAsync(500L)
    }

    private fun enterPanic(reason: String) {
        _currentState.value = RecoveryState.PANIC_MODE
        if (!BypassConfig.isPanicMode) {
            Log.w(TAG, "Triggering Panic Mode: $reason")
            ProxyStats.clearCensorshipHistory()
            BypassConfig.panicOptimize()
        }
    }

    private fun requestTunnelRestart(reason: String) {
        val now = System.currentTimeMillis()
        if (now - lastRestartTimestamp < restartCooldownMs) {
            Log.w(TAG, "Skipping tunnel restart: cooldown active ($reason)")
            return
        }

        lastRestartTimestamp = now
        restartCooldownMs = (restartCooldownMs * 1.5).toLong().coerceAtMost(300000L)
        _currentState.value = RecoveryState.RESTARTING_TUNNEL
        escalationLevel.set(0)

        Log.e(TAG, "Executing coordinated tunnel restart: $reason")
        val context = PinkVpnService.instance ?: ProxyDispatcher.context ?: return
        VpnRecoveryCoordinator(context).triggerRestart()
    }

    private fun triggerActiveProbeAsync(delayMs: Long) {
        val scope = machineScope ?: PinkVpnService.instance?.getServiceScope() ?: ProxyDispatcher.mainScope
        scope.launch(ProxyDispatcher.io) {
            delay(delayMs)
            val ctx = PinkVpnService.instance ?: ProxyDispatcher.context
            if (ctx != null) {
                _currentState.value = RecoveryState.PROBING
                ServiceChecker.runActiveProbing(ctx)
                _currentState.value = if (BypassConfig.isPanicMode) RecoveryState.PANIC_MODE else RecoveryState.IDLE
            }
        }
    }

    fun coolDownEscalation(reduction: Int = 1) {
        val current = escalationLevel.get()
        if (current > 0) {
            val updated = (current - reduction).coerceAtLeast(0)
            escalationLevel.set(updated)
            if (updated == 0 && _currentState.value == RecoveryState.PANIC_MODE) {
                _currentState.value = RecoveryState.IDLE
                BypassConfig.setPanicMode(false)
            }
        }
    }
}
