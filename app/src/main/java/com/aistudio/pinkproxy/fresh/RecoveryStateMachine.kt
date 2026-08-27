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
    abstract val transport: TransportType?

    interface HostLevelRecoverySignal {
        val host: String?
        val category: HostCategory
    }

    interface TunnelLevelRecoverySignal

    data class DpiDetected(val type: DpiType, override val host: String? = null, override val transport: TransportType, override val category: HostCategory = HostCategory.OTHER) : RecoverySignal(), HostLevelRecoverySignal
    data class TunnelStall(val durationMs: Long, val activeConnections: Int, override val transport: TransportType) : RecoverySignal(), TunnelLevelRecoverySignal
    data class TcpStall(override val host: String, val strategy: BypassStrategy, override val transport: TransportType, override val category: HostCategory = HostCategory.OTHER) : RecoverySignal(), HostLevelRecoverySignal
    data class SslStall(override val host: String, val strategy: BypassStrategy, override val transport: TransportType, override val category: HostCategory = HostCategory.OTHER) : RecoverySignal(), HostLevelRecoverySignal
    data class DnsFailure(val domain: String, val isPoisoned: Boolean, override val transport: TransportType = TransportType.DNS, override val category: HostCategory = HostCategory.OTHER) : RecoverySignal(), HostLevelRecoverySignal {
        override val host: String get() = domain
    }
    data class ProxyUnresponsive(val reason: String, override val transport: TransportType) : RecoverySignal(), TunnelLevelRecoverySignal
    data class MemoryPressure(val usedPercent: Int) : RecoverySignal() {
        override val transport: TransportType? = null
    }
    data class ExtremeLatency(val latencyMs: Long, override val transport: TransportType) : RecoverySignal(), TunnelLevelRecoverySignal
    data class HealthDegraded(val details: String, override val transport: TransportType) : RecoverySignal(), TunnelLevelRecoverySignal
    data class NetworkLost(val networkType: String) : RecoverySignal() {
        override val transport: TransportType? = null
    }
    object ManualReset : RecoverySignal() {
        override val transport: TransportType? = null
    }
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
        dnsFailureCount.set(0)
        Log.i(TAG, "RecoveryStateMachine initialized in IDLE state")
    }

    fun stop() {
        machineScope = null
        _currentState.value = RecoveryState.IDLE
        dnsFailureCount.set(0)
    }

    /**
     * Dispatch an event to the state machine asynchronously.
     */
    fun postSignal(signal: RecoverySignal): Job {
        val scope = machineScope ?: PinkVpnService.instance?.getServiceScope() ?: ProxyDispatcher.mainScope
        return scope.launch(ProxyDispatcher.io) {
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

    private suspend fun processDpiSignal(signal: RecoverySignal.DpiDetected) {
        _currentState.value = RecoveryState.DEGRADED
        val type = signal.type
        val targetHost = signal.host
        val transport = signal.transport
        val profileId = NetworkProfileManager.currentProfile.value.id
        val category = targetHost?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
        when (type) {
            DpiType.TCP_RESET -> {
                val candidates = listOf(
                    BypassStrategy.TCP_COMBINED_NUCLEAR,
                    BypassStrategy.TCP_COMBINED_HYBRID,
                    BypassStrategy.TCP_DATA_DESYNC_OVERLAP,
                    BypassStrategy.OOB_DESYNC
                ).filter { StrategyExecutionRegistry.isExecutorSupported(it, TransportType.TCP) }
                val selected = candidates.maxWithOrNull(
                    compareBy<BypassStrategy> { DpiStrategySelector.getScore(it, TransportType.TCP, category, profileId) }
                        .thenBy { it.name.hashCode() }
                ) ?: BypassStrategy.TCP_COMBINED_NUCLEAR
                if (targetHost != null) {
                    RuntimeCoordinator.requestGlobalStrategyRotation(transport, "DPI Signal Escalation", category, host = targetHost)
                } else {
                    RuntimeCoordinator.applyStrategyTransition(selected, TransportType.TCP, "Active TCP Reset DPI detected")
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
                    compareBy<BypassStrategy> { DpiStrategySelector.getScore(it, TransportType.TCP, category, profileId) }
                        .thenBy { it.name.hashCode() }
                ) ?: BypassStrategy.SNI_SPLIT
                if (targetHost != null) {
                    RuntimeCoordinator.requestGlobalStrategyRotation(transport, "DPI Signal Escalation", category, host = targetHost)
                } else {
                    RuntimeCoordinator.applyStrategyTransition(selected, TransportType.TCP, "TLS SNI Block Detected")
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
                    compareBy<BypassStrategy> { DpiStrategySelector.getScore(it, TransportType.TCP, category, profileId) }
                        .thenBy { it.name.hashCode() }
                ) ?: BypassStrategy.HTTP_HOST_SPACE
                if (targetHost != null) {
                    RuntimeCoordinator.requestGlobalStrategyRotation(transport, "DPI Signal Escalation", category, host = targetHost)
                } else {
                    RuntimeCoordinator.applyStrategyTransition(selected, TransportType.TCP, "HTTP Block Detected")
                }
            }
            DpiType.CONNECTION_TIMEOUT -> {
                val candidates = listOf(
                    BypassStrategy.TLS_REC_SPLIT, 
                    BypassStrategy.TCP_ACK_SKEW, 
                    BypassStrategy.TCP_WINDOW_SIZE_CHAOS
                ).filter { StrategyExecutionRegistry.isExecutorSupported(it, transport) }
                val selected = candidates.maxWithOrNull(
                    compareBy<BypassStrategy> { DpiStrategySelector.getScore(it, transport, category, profileId) }
                        .thenBy { it.name.hashCode() }
                ) ?: DpiStrategySelector.getDefaultFallback(transport)
                if (targetHost != null) {
                    RuntimeCoordinator.requestGlobalStrategyRotation(transport, "DPI Signal Escalation", category, host = targetHost)
                } else {
                    RuntimeCoordinator.applyStrategyTransition(selected, transport, "DPI Timeout Escalation")
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
                    compareBy<BypassStrategy> { DpiStrategySelector.getScore(it, TransportType.UDP, category, profileId) }
                        .thenBy { it.name.hashCode() }
                ) ?: BypassStrategy.UDP_COMBINED_NUCLEAR
                if (targetHost != null) {
                    RuntimeCoordinator.requestGlobalStrategyRotation(transport, "DPI Signal Escalation", category, host = targetHost)
                } else {
                    RuntimeCoordinator.applyStrategyTransition(selected, TransportType.UDP, "UDP Block Detected")
                }
            }
            else -> {
                RuntimeCoordinator.requestGlobalStrategyRotation(transport, "DPI Signal Escalation", HostCategory.OTHER, host = targetHost)
            }
        }

        escalationLevel.set((escalationLevel.get() + 1).coerceAtMost(3))
        triggerActiveProbeAsync(3000L)
    }    private fun processTunnelStall(durationMs: Long, activeConns: Int, transport: TransportType) {
        val currentEsc = escalationLevel.get()
        if (currentEsc < 3) {
            _currentState.value = RecoveryState.RECONFIGURING_MTU
            RuntimeCoordinator.requestGlobalStrategyRotation(transport, "Watchdog Tunnel Stall Rotation", HostCategory.OTHER)

            // Dynamic TTL shifting
            val nextTtl = when (BypassConfig.currentTtl) {
                3 -> 5
                5 -> 8
                8 -> 10
                else -> 3
            }
            BypassConfig.setTtl(nextTtl)

            // Reduce MTU
            val currentMtu = BypassConfig.getMtuForTransport(TransportType.TCP)
            if (currentMtu > 1100) {
                val reduction = 80
                BypassConfig.setMtu(currentMtu - reduction)
                ProxyStats.logRecovery("Watchdog: Reducing MTU to ${currentMtu - reduction} due to tunnel stall")
            }

            escalationLevel.incrementAndGet()
            triggerActiveProbeAsync(2000L)
        } else {
            enterPanic("Critical tunnel stall ($durationMs ms, $activeConns conns)")
            requestTunnelRestart("Persistent tunnel stall")
        }
    }

    private suspend fun processSocketStall(signal: RecoverySignal) {
        _currentState.value = RecoveryState.DEGRADED
        
        val transport = signal.transport ?: TransportType.TCP
        val targetHost = (signal as? RecoverySignal.HostLevelRecoverySignal)?.host
        val category = (signal as? RecoverySignal.HostLevelRecoverySignal)?.category ?: HostCategory.OTHER
        
        val failedStrategy = when (signal) {
            is RecoverySignal.TcpStall -> signal.strategy
            is RecoverySignal.SslStall -> signal.strategy
            else -> null
        }
        
        RuntimeCoordinator.requestGlobalStrategyRotation(
            transport = transport, 
            reason = "Socket Stall Recovery", 
            category = category, 
            host = targetHost,
            failedStrategy = failedStrategy
        )

        val currentMtu = BypassConfig.getMtuForTransport(TransportType.TCP)
        if (currentMtu > 1100) {
            BypassConfig.setMtu(currentMtu - 150)
            ProxyStats.logRecovery("Stall Handler: Reduced MTU to ${currentMtu - 150}")
        }
        escalationLevel.incrementAndGet()
        triggerActiveProbeAsync(2000L)
    }

    private val dnsFailureCount = java.util.concurrent.atomic.AtomicInteger(0)

    fun resetDnsFailures() {
        dnsFailureCount.set(0)
    }

    private fun processDnsFailure(signal: RecoverySignal.DnsFailure) {
        _currentState.value = RecoveryState.DEGRADED
        RobustResolver.clearCache()
        DnsCacheManager.clearAll()
        DnsOptimizer.forceRefresh()

        val count = dnsFailureCount.incrementAndGet()
        Log.w(TAG, "DNS failure registered ($count consecutive): ${signal.domain} (poisoned=${signal.isPoisoned})")

        if (signal.isPoisoned) {
            enterPanic("DNS Poisoning detected for ${signal.domain}")
            RobustResolver.dnsMode = "Smart DoH"
            DnsOptimizer.selectNextBestResolver()
        } else {
            DnsOptimizer.selectNextBestResolver()
        }

        if (count < 5) {
            // Early stages: rotate DoH/DoT resolver and clear cache without restarting tunnel
            triggerActiveProbeAsync(1000L)
        } else if (count < 10) {
            enterPanic("Repeated DNS failures across resolvers")
            RobustResolver.dnsMode = "Smart DoH"
        } else {
            dnsFailureCount.set(0)
            requestTunnelRestart("Persistent DNS failures across all resolvers")
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

    private suspend fun processExtremeLatency(latencyMs: Long, transport: TransportType) {
        _currentState.value = RecoveryState.DEGRADED
        RuntimeCoordinator.requestGlobalStrategyRotation(transport, "Recovery: Extreme Latency ($latencyMs ms)", HostCategory.OTHER)
        escalationLevel.set((escalationLevel.get() + 1).coerceAtMost(2))
    }

    private suspend fun processHealthDegraded(details: String, transport: TransportType) {
        _currentState.value = RecoveryState.DEGRADED
        RuntimeCoordinator.requestGlobalStrategyRotation(transport, "Recovery: Health Degraded ($details)", HostCategory.OTHER)
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
        DpiPolicyEngine.resetProfileEngineStates(NetworkProfileManager.currentProfile.value.id)
        DnsCacheManager.clearAll()
        RobustResolver.clearCache()
        DnsOptimizer.forceRefresh()
        escalationLevel.set(0)
        dnsFailureCount.set(0)
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
