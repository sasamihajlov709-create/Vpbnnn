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
        .stateIn(CoroutineScope(Dispatchers.Default), SharingStarted.Eagerly, emptyList())

    fun registerFlow(id: String, host: String, type: String, strategy: BypassStrategy) {
        _activeFlows.update { it + (id to ActiveFlow(id, host, type, strategy)) }
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
        CoroutineScope(Dispatchers.Default).launch {
            delay(5000)
            removeFlow(id)
        }
    }

    private val _dpiEventHistory = MutableStateFlow(emptyList<DpiEvent>())
    val dpiEventHistory: StateFlow<List<DpiEvent>> = _dpiEventHistory.asStateFlow()

    private val _currentDpiType = MutableStateFlow(DpiType.NONE)
    val currentDpiType: StateFlow<DpiType> = _currentDpiType.asStateFlow()

    fun recordDpiEvent(type: DpiType) {
        _currentDpiType.value = type
        _dpiEventHistory.update { current ->
            (current + DpiEvent(type)).takeLast(50)
        }
        dpiEvents.compute(type) { _, current -> (current ?: 0) + 1 }
        VpnRuntimeState.updateDpi(type.name)
        recordCensorshipEvent(true)
        DpiEngine.recordEvent(type)
        logRecovery("Detected censorship type: $type")
    }
    
    val dpiEvents = ConcurrentHashMap<DpiType, Int>()
    fun resetDpiEvent(type: DpiType) { dpiEvents[type] = 0 }
    
    fun recordDnsFailure() {
        _dnsFailureCount.update { it + 1 }
        recordCensorshipEvent(true)
        DpiEngine.recordEvent(DpiType.DNS_POISONING)
    }
    
    fun clearDpiType() {
        _currentDpiType.value = DpiType.NONE
    }

    private val _lastLatency = MutableStateFlow(0L)
    val lastLatency: StateFlow<Long> = _lastLatency.asStateFlow()

    private val _jitter = MutableStateFlow(0L)
    val jitter: StateFlow<Long> = _jitter.asStateFlow()

    fun updateLatency(ms: Long) {
        val old = _lastLatency.value
        if (old > 0) {
            val diff = Math.abs(ms - old)
            _jitter.value = (_jitter.value * 3 + diff) / 4
        }
        _lastLatency.value = ms
    }

    private val bufferPool8k = java.util.concurrent.ConcurrentLinkedQueue<ByteArray>()
    private val bufferPool16k = java.util.concurrent.ConcurrentLinkedQueue<ByteArray>()
    private val bufferPool64k = java.util.concurrent.ConcurrentLinkedQueue<ByteArray>()

    fun obtain8k(): ByteArray = bufferPool8k.poll() ?: ByteArray(8192)
    fun release8k(buf: ByteArray) { if (buf.size >= 8192 && bufferPool8k.size < 512) bufferPool8k.offer(buf) }

    fun obtain16k(): ByteArray = bufferPool16k.poll() ?: ByteArray(16384)
    fun release16k(buf: ByteArray) { if (buf.size >= 16384 && bufferPool16k.size < 256) bufferPool16k.offer(buf) }

    fun obtain64k(): ByteArray = bufferPool64k.poll() ?: ByteArray(65536)
    fun release64k(buf: ByteArray) { if (buf.size >= 65536 && bufferPool64k.size < 64) bufferPool64k.offer(buf) }

    fun releasePool(buf: ByteArray) {
        when (buf.size) {
            8192 -> release8k(buf)
            16384 -> release16k(buf)
            65536 -> release64k(buf)
        }
    }

    fun releaseAllPools() {
        bufferPool8k.clear()
        bufferPool16k.clear()
        bufferPool64k.clear()
    }

    private val strategySuccessMap = ConcurrentHashMap<BypassStrategy, Int>()
    private val strategyFailureMap = ConcurrentHashMap<BypassStrategy, Int>()

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
        _censorshipIntensity.value = 0
        _stabilityScore.value = 100
        dpiEvents.clear()
        _errors.value = 0
        _successRate.value = 100
    }

    private val _bytesTransferred = MutableStateFlow(0L)
    val bytesTransferred: StateFlow<Long> = _bytesTransferred.asStateFlow()
    
    private val rawBytesTransferred = AtomicLong(0)
    fun updateBytes(delta: Long) { rawBytesTransferred.addAndGet(delta) }

    private val _activeConnections = MutableStateFlow(0)
    val activeConnections: StateFlow<Int> = _activeConnections.asStateFlow()

    private val _speedBytesPerSecond = MutableStateFlow(0L)
    val speedBytesPerSecond: StateFlow<Long> = _speedBytesPerSecond.asStateFlow()

    private val _speedHistory = MutableStateFlow(emptyList<Long>())
    val speedHistory: StateFlow<List<Long>> = _speedHistory.asStateFlow()

    private val _errors = MutableStateFlow(0L)
    val errors: StateFlow<Long> = _errors.asStateFlow()

    private val _censorshipIntensity = MutableStateFlow(0)
    val censorshipIntensity: StateFlow<Int> = _censorshipIntensity.asStateFlow()

    fun updateCensorshipIntensity(newVal: Int) { _censorshipIntensity.value = newVal.coerceIn(0, 100) }

    fun clearCensorshipHistory() { _censorshipIntensity.value = 0 }

    fun recordCensorshipEvent(isFailure: Boolean) {
        if (isFailure) {
            _errors.update { it + 1 }
            _successRate.update { (it * 0.85 + 0).toInt().coerceIn(0, 100) }
            _censorshipIntensity.update { (it + 8).coerceAtMost(100) }
        } else {
            _successRate.update { (it * 0.98 + 2).toInt().coerceIn(0, 100) }
            _censorshipIntensity.update { (it - 2).coerceAtLeast(0) }
        }
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

    private val _signalQuality = MutableStateFlow(100)
    val signalQuality: StateFlow<Int> = _signalQuality.asStateFlow()

    private val _topHosts = MutableStateFlow(emptyList<Pair<String, Int>>())
    val topHosts: StateFlow<List<Pair<String, Int>>> = _topHosts.asStateFlow()

    private val _pool8kSize = MutableStateFlow(0)
    val pool8kSize: StateFlow<Int> = _pool8kSize.asStateFlow()

    private val _pool16kSize = MutableStateFlow(0)
    val pool16kSize: StateFlow<Int> = _pool16kSize.asStateFlow()

    private val _pool64kSize = MutableStateFlow(0)
    val pool64kSize: StateFlow<Int> = _pool64kSize.asStateFlow()

    private val _congestionWindow = MutableStateFlow(10)
    val congestionWindow: StateFlow<Int> = _congestionWindow.asStateFlow()

    private val _dnsSuccessCount = MutableStateFlow(0L)
    val dnsSuccessCount: StateFlow<Long> = _dnsSuccessCount.asStateFlow()

    private val _dnsFailureCount = MutableStateFlow(0L)
    val dnsFailureCount: StateFlow<Long> = _dnsFailureCount.asStateFlow()

    private val _stabilityScore = MutableStateFlow(100)
    val stabilityScore: StateFlow<Int> = _stabilityScore.asStateFlow()

    private val _successRate = MutableStateFlow(100)
    val successRate: StateFlow<Int> = _successRate.asStateFlow()

    fun updateStabilityScore(newVal: Int) { _stabilityScore.value = newVal.coerceIn(0, 100) }
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
        rawBytesTransferred.set(0)
        _bytesTransferred.value = 0
        _errors.value = 0
        _speedHistory.value = emptyList()
        _speedBytesPerSecond.value = 0
        _signalQuality.value = 100
        _topHosts.value = emptyList()
        _congestionWindow.value = 10
        _dnsSuccessCount.value = 0
        _dnsFailureCount.value = 0
        _stabilityScore.value = 100
        _successRate.value = 100
        if (clearLog) {
            _recoveryLog.value = emptyList()
            _trafficLog.value = emptyList()
        }
    }

    fun startSpeedMonitor(scope: CoroutineScope) {
        scope.launch {
            var lastBytes = rawBytesTransferred.get()
            var lastCleanup = System.currentTimeMillis()
            while (isActive) {
                delay(1000)
                val now = System.currentTimeMillis()
                
                if (now - lastCleanup > 300000) {
                    DnsCacheManager.ageHeatmap()
                    DnsCacheManager.clearExpired()
                    lastCleanup = now
                }

                val currentBytes = rawBytesTransferred.get()
                _bytesTransferred.value = currentBytes
                val speed = (currentBytes - lastBytes).coerceAtLeast(0)
                _speedBytesPerSecond.value = speed
                
                val baseQual = _successRate.value.coerceIn(0, 100)
                val stabPenalty = (100 - _stabilityScore.value) / 2
                val panicPenalty = if (BypassConfig.isPanicModeFlow.value) 15 else 0
                val intensityPenalty = (ProxyStats.censorshipIntensity.value / 10).coerceAtMost(10)
                
                val finalQual = (baseQual - stabPenalty - panicPenalty - intensityPenalty).coerceIn(0, 100)
                _signalQuality.value = finalQual

                _speedHistory.update { current ->
                    val newList = ArrayList<Long>(60)
                    newList.add(speed)
                    if (current.size > 59) newList.addAll(current.subList(0, 59)) else newList.addAll(current)
                    newList
                }
                
                lastBytes = currentBytes
                _pool8kSize.value = bufferPool8k.size
                _pool16kSize.value = bufferPool16k.size
                _pool64kSize.value = bufferPool64k.size
                
                if (successRate.value < 40 && ProxyStats.activeConnections.value > 0) {
                    if (!BypassConfig.isPanicModeFlow.value) {
                        logRecovery("Critical success rate drop (${successRate.value}%). Activating Panic Mode.")
                        BypassConfig.setPanicMode(true)
                    }
                } else if (successRate.value > 85 && BypassConfig.isPanicModeFlow.value) {
                    logRecovery("Stability restored (${successRate.value}%). Deactivating Panic Mode.")
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
        return String.format(Locale.ROOT, "%.1f %sB", bytes / Math.pow(1024.0, exp.toDouble()), pre)
    }

    fun recordGlobalSuccess(rtt: Long) {
        if (rtt > 0) {
             val lastRtt = _lastLatency.value
             val jitter = Math.abs(rtt - lastRtt)
             val jitterPenalty = (jitter / 10).coerceAtMost(30)
             _stabilityScore.update { (it * 0.95 + (100 - jitterPenalty) * 0.05).toInt().coerceIn(0, 100) }
             updateLatency(rtt)
        }
        _censorshipIntensity.update { (it - 3).coerceAtLeast(0) }
        _successRate.update { (it * 0.97 + 3).toInt().coerceIn(0, 100) }
    }

    fun recordGlobalFailure() {
        _censorshipIntensity.update { (it + 5).coerceAtMost(100) }
        _successRate.update { (it * 0.98).toInt().coerceIn(0, 100) }
        _stabilityScore.update { (it - 3).coerceAtLeast(0) }
    }

    fun addTraffic(host: String) {
        _trafficLog.update { current -> (listOf(host) + current).take(50) }
        _topHosts.update { current ->
            val hosts = current.toMutableList()
            val idx = hosts.indexOfFirst { it.first == host }
            if (idx != -1) hosts[idx] = host to hosts[idx].second + 1 else hosts.add(host to 1)
            hosts.sortedByDescending { it.second }.take(10)
        }
    }

    fun updateConnections(delta: Int) { _activeConnections.update { (it + delta).coerceAtLeast(0) } }
    fun getSuccessRate() = _successRate.value
}
