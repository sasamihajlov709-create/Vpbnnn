package com.aistudio.pinkproxy.fresh

import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

object ProxyStats {
    private val _activeFlows = MutableStateFlow<Map<String, ActiveFlow>>(emptyMap())
    val activeFlows: StateFlow<List<ActiveFlow>> = _activeFlows.map { it.values.toList().sortedByDescending { f -> f.startTime } }
        .stateIn(ProxyDispatcher.mainScope, SharingStarted.Eagerly, emptyList())

    fun registerFlow(id: String, host: String, type: String, strategy: BypassStrategy, reasoning: String = "") {
        _activeFlows.update { it + (id to ActiveFlow(id, host, type, strategy, reasoning = reasoning)) }
    }

    fun updateFlow(id: String, sent: Long = 0, received: Long = 0, status: String? = null) {
        _activeFlows.update { current ->
            current[id]?.let { flow ->
                val updated = flow.copy(
                    bytesSent = flow.bytesSent + sent,
                    bytesReceived = flow.bytesReceived + received,
                    status = status ?: flow.status
                )
                current + (id to updated)
            } ?: current
        }
    }

    fun removeFlow(id: String) {
        _activeFlows.update { it - id }
    }

    fun closeFlow(id: String) {
        updateFlow(id, status = "CLOSED")
        ProxyDispatcher.mainScope.launch {
            delay(5000)
            removeFlow(id)
        }
    }

    val dpiEventHistory = StabilityAnalyzer.dpiEventHistory
    val currentDpiType = StabilityAnalyzer.currentDpiType

    fun recordDpiEvent(type: DpiType) {
        StabilityAnalyzer.recordDpi(type)
        dpiEvents.compute(type) { _, current -> (current ?: 0) + 1 }
        VpnRuntimeState.updateDpi(type.name)
        recordCensorshipEvent(true)
        DpiEngine.recordEvent(type)
        logRecovery("Detected censorship type: $type")
    }
    
    val dpiEvents = java.util.concurrent.ConcurrentHashMap<DpiType, Int>()
    fun resetDpiEvent(type: DpiType) { dpiEvents[type] = 0 }
    
    fun recordDnsFailure() {
        _dnsFailureCount.update { it + 1 }
        recordCensorshipEvent(true)
        DpiEngine.recordEvent(DpiType.DNS_POISONING)
    }
    
    fun clearDpiType() {
        StabilityAnalyzer.reset() // Or just reset DPI specific part
    }

    val lastLatency = StabilityAnalyzer.lastLatency
    val jitter = StabilityAnalyzer.jitter

    fun updateLatency(ms: Long) {
        StabilityAnalyzer.updateLatency(ms)
    }

    fun obtain8k(): ByteArray = BufferPoolManager.obtain8k()
    fun release8k(buf: ByteArray) = BufferPoolManager.release8k(buf)
    fun obtain16k(): ByteArray = BufferPoolManager.obtain16k()
    fun release16k(buf: ByteArray) = BufferPoolManager.release16k(buf)
    fun obtain64k(): ByteArray = BufferPoolManager.obtain64k()
    fun release64k(buf: ByteArray) = BufferPoolManager.release64k(buf)
    fun releasePool(buf: ByteArray) = BufferPoolManager.releasePool(buf)
    fun releaseAllPools() = BufferPoolManager.releaseAllPools()

    private val strategySuccessMap = java.util.concurrent.ConcurrentHashMap<BypassStrategy, Int>()
    private val strategyFailureMap = java.util.concurrent.ConcurrentHashMap<BypassStrategy, Int>()

    fun reportStrategyResult(strategy: BypassStrategy, success: Boolean) {
        if (success) {
            strategySuccessMap.compute(strategy) { _, current -> (current ?: 0) + 1 }
            strategyFailureMap.compute(strategy) { _, current -> ((current ?: 0) - 1).coerceAtLeast(0) }
        } else {
            strategyFailureMap.compute(strategy) { _, current -> (current ?: 0) + 1 }
        }
    }

    fun getStrategyScore(strategy: BypassStrategy): Int {
        val success = strategySuccessMap[strategy] ?: 0
        val failure = strategyFailureMap[strategy] ?: 0
        return success - (failure * 2)
    }

    fun resetScores() {
        strategySuccessMap.clear()
        strategyFailureMap.clear()
        StabilityAnalyzer.reset()
        _errors.value = 0
    }

    val bytesTransferred = TrafficMonitor.bytesTransferred
    fun updateBytes(delta: Long) = TrafficMonitor.updateBytes(delta)

    val activeConnections = TrafficMonitor.activeConnections
    fun updateConnections(delta: Int) = TrafficMonitor.updateConnections(delta)

    val speedBytesPerSecond = TrafficMonitor.speedBytesPerSecond
    val speedHistory = TrafficMonitor.speedHistory

    private val _errors = MutableStateFlow(0L)
    val errors: StateFlow<Long> = _errors.asStateFlow()

    val censorshipIntensity = StabilityAnalyzer.censorshipIntensity
    fun updateCensorshipIntensity(newVal: Int) { StabilityAnalyzer.setCensorshipIntensity(newVal) }
    fun clearCensorshipHistory() { StabilityAnalyzer.reset() }

    fun recordCensorshipEvent(isFailure: Boolean) {
        if (isFailure) _errors.update { it + 1 }
        StabilityAnalyzer.recordEvent(isFailure)
    }

    private val _recoveryLog = MutableStateFlow(emptyList<String>())
    val recoveryLog: StateFlow<List<String>> = _recoveryLog.asStateFlow()

    private val _trafficLog = MutableStateFlow(emptyList<String>())
    val trafficLog: StateFlow<List<String>> = _trafficLog.asStateFlow()

    fun logRecovery(msg: String) {
        Log.i("ProxyStats", "RECOVERY: $msg")
        _recoveryLog.update { (it + msg).takeLast(100) }
    }

    fun logTraffic(msg: String) {
        Log.v("ProxyStats", "TRAFFIC: $msg")
        _trafficLog.update { (it + msg).takeLast(100) }
    }

    val signalQuality = StabilityAnalyzer.signalQuality
    val topHosts = TrafficMonitor.topHosts

    val pool8kSize = MutableStateFlow(0)
    val pool16kSize = MutableStateFlow(0)
    val pool64kSize = MutableStateFlow(0)

    private val _congestionWindow = MutableStateFlow(10)
    val congestionWindow: StateFlow<Int> = _congestionWindow.asStateFlow()

    private val _dnsSuccessCount = MutableStateFlow(0L)
    val dnsSuccessCount: StateFlow<Long> = _dnsSuccessCount.asStateFlow()

    private val _dnsFailureCount = MutableStateFlow(0L)
    val dnsFailureCount: StateFlow<Long> = _dnsFailureCount.asStateFlow()

    val stabilityScore = StabilityAnalyzer.stabilityScore
    val successRate = StabilityAnalyzer.successRate

    fun updateStabilityScore(newVal: Int) { StabilityAnalyzer.setStabilityScore(newVal) }
    fun updateCongestionWindow(delta: Int) { _congestionWindow.update { (it + delta).coerceIn(1, 1000) } }

    private val _maxMss = MutableStateFlow(1460)
    val maxMss: StateFlow<Int> = _maxMss.asStateFlow()
    fun updateMaxMss(newMss: Int) { _maxMss.value = newMss }

    private val _mssFailureCount = MutableStateFlow(0)
    val mssFailureCount: StateFlow<Int> = _mssFailureCount.asStateFlow()
    
    fun recordMssFailure() {
        _mssFailureCount.update { current ->
            val newVal = current + 1
            logRecovery("MTU auto-correction: incrementing MSS failure count to $newVal")
            if (newVal >= 3) {
                val currentMss = _maxMss.value
                if (currentMss > 512) {
                    val nextMss = (currentMss - 128).coerceAtLeast(512)
                    _maxMss.value = nextMss
                    logRecovery("MTU auto-correction: Reducing Max MSS to $nextMss")
                    0
                } else newVal
            } else newVal
        }
    }
    
    fun resetMssFailureCount() { _mssFailureCount.value = 0 }

    fun recordDnsResult(success: Boolean) {
        if (success) {
            _dnsSuccessCount.update { it + 1 }
            _dnsFailureCount.value = 0
            recordGlobalSuccess(0)
        } else {
            _dnsFailureCount.update { it + 1 }
            recordCensorshipEvent(true)
        }
    }

    fun forceRecovery(reason: String) {
        RecoveryManager.handleEvent(RecoveryEvent.PROXY_UNREACHABLE, "Manual trigger: $reason")
    }
    
    fun reset(clearLog: Boolean) {
        TrafficMonitor.reset()
        StabilityAnalyzer.reset()
        _errors.value = 0
        _dnsSuccessCount.value = 0
        _dnsFailureCount.value = 0
        if (clearLog) {
            _recoveryLog.value = emptyList()
            _trafficLog.value = emptyList()
        }
    }

    fun startSpeedMonitor(scope: CoroutineScope) {
        scope.launch {
            var lastCleanup = System.currentTimeMillis()
            var lastThrottleCheck = System.currentTimeMillis()
            while (isActive) {
                delay(1000)
                val now = System.currentTimeMillis()
                
                if (now - lastCleanup > 300000) {
                    DnsCacheManager.ageHeatmap()
                    DnsCacheManager.clearExpired()
                    lastCleanup = now
                }

                TrafficMonitor.updateSpeedMetrics()
                
                // Speed-based Auto-Recovery
                val currentSpeed = TrafficMonitor.speedBytesPerSecond.value
                val activeConns = TrafficMonitor.activeConnections.value
                if (activeConns > 0 && currentSpeed < 50 * 1024 && now - lastThrottleCheck > 15000) { // < 50KB/s with active conns
                    if (StabilityAnalyzer.successRate.value > 70) { // Success rate is fine, but speed is low (likely throttled)
                        logRecovery("Low throughput detected (${currentSpeed / 1024} KB/s). Triggering fragment re-calibration.")
                        DpiEngine.triggerRecalibration()
                        lastThrottleCheck = now
                    }
                }

                StabilityAnalyzer.updateSignalQuality(
                    successRate = StabilityAnalyzer.successRate.value,
                    stabilityScore = StabilityAnalyzer.stabilityScore.value,
                    censorshipIntensity = StabilityAnalyzer.censorshipIntensity.value,
                    isPanicMode = BypassConfig.isPanicModeFlow.value
                )

                pool8kSize.value = BufferPoolManager.get8kSize()
                pool16kSize.value = BufferPoolManager.get16kSize()
                pool64kSize.value = BufferPoolManager.get64kSize()
                
                if (StabilityAnalyzer.successRate.value < 40 && TrafficMonitor.activeConnections.value > 0) {
                    if (!BypassConfig.isPanicModeFlow.value) {
                        logRecovery("Critical success rate drop (${StabilityAnalyzer.successRate.value}%). Activating Panic Mode.")
                        BypassConfig.setPanicMode(true)
                    }
                } else if (StabilityAnalyzer.successRate.value > 85 && BypassConfig.isPanicModeFlow.value) {
                    logRecovery("Stability restored (${StabilityAnalyzer.successRate.value}%). Deactivating Panic Mode.")
                    BypassConfig.setPanicMode(false)
                }
            }
        }
    }

    fun formatBytes(bytes: Long): String {
        if (bytes <= 0) return "0 B"
        if (bytes < 1024) return "$bytes B"
        val exp = (Math.log(bytes.toDouble()) / Math.log(1024.0)).toInt()
        val pre = "KMGTPE"[exp - 1].toString()
        return String.format(java.util.Locale.ROOT, "%.1f %sB", bytes / Math.pow(1024.0, exp.toDouble()), pre)
    }

    fun recordGlobalSuccess(rtt: Long) {
        StabilityAnalyzer.recordEvent(false, rtt)
    }

    fun recordGlobalFailure() {
        StabilityAnalyzer.recordEvent(true)
    }

    fun addTraffic(host: String) {
        _trafficLog.update { current -> (listOf(host) + current).take(50) }
        TrafficMonitor.addTraffic(host)
    }

    fun recordStats(id: String, sent: Long = 0, received: Long = 0) {
        updateFlow(id, sent, received)
        updateBytes(sent + received)
    }

    fun unregisterFlow(id: String, success: Boolean) {
        recordCensorshipEvent(!success)
        closeFlow(id)
    }
}
