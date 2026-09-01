package com.aistudio.pinkproxy.fresh

import android.content.Context
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.LinkedList
import java.util.Collections

data class DpiEventKey(
    val profileId: String,
    val transport: TransportType,
    val type: DpiType
)

object DpiEngine {
    
    private val _currentDpiLevel = MutableStateFlow(0)
    val currentDpiLevel = _currentDpiLevel.asStateFlow()


    val eventHistory = ConcurrentHashMap<DpiEventKey, AtomicInteger>()
    val rttHistory = ConcurrentHashMap<String, MutableList<Long>>()


    private var lastGlobalReset = System.currentTimeMillis()
    private var lastPanicTime = 0L

    val isPanicMode: StateFlow<Boolean> get() = BypassConfig.isPanicModeFlow

    private var optimizerJob: Job? = null
    private var microProbeJob: Job? = null
    private var appContext: Context? = null

    private val profileChangeListener: (NetworkProfile, NetworkProfile) -> Unit = { oldProfile, newProfile ->
        switchNetworkProfile(oldProfile, newProfile, appContext)
    }

    fun start(context: Context) {
        stop()
        val ctx = context.applicationContext
        appContext = ctx
        DpiStorage.loadScores(ctx)
        NetworkProfileManager.addListener(profileChangeListener)
        
        optimizerJob = (VpnSessionManager.currentSession?.learningScope ?: ProxyDispatcher.globalScope).launch {
            while (isActive) {
                delay(15000)
                DpiAnalyzer.analyzeAndAdjust()
            }
        }
    }

    fun stop() {
        NetworkProfileManager.removeListener(profileChangeListener)
        microProbeJob?.cancel()
        microProbeJob = null
        optimizerJob?.cancel()
        optimizerJob = null
        appContext?.let { DpiStorage.saveProfileScores(it, NetworkProfileManager.currentProfile.value.id) }
        appContext = null
    }

    fun switchNetworkProfile(oldProfile: NetworkProfile, newProfile: NetworkProfile, context: Context?) {
        Log.i("DpiEngine", "Network Profile Changed: ${oldProfile.id} -> ${newProfile.id}")
        context?.let {
            DpiStorage.saveProfileScores(it, oldProfile.id)
            DpiStorage.loadScores(it)
        }
        resetStrategyScoresForNetworkChange()
    }

    private fun resetStrategyScoresForNetworkChange() {
        Log.i("DpiEngine", "Resetting profile states due to network change.")
        DpiPolicyEngine.resetProfileEngineStates(NetworkProfileManager.currentProfile.value.id)
    }

    fun markSuccess(strat: BypassStrategy, transport: TransportType, host: String, latencyMs: Long = 0, quality: ObservationQuality) {
        if (latencyMs > 0) {
            val key = "${NetworkProfileManager.currentProfile.value.id}|$transport"
            val list = rttHistory.getOrPut(key) { java.util.Collections.synchronizedList(java.util.LinkedList<Long>()) }
            list.add(latencyMs)
            if (list.size > 50) list.removeAt(0)
        }
        val category = HostClassifier.classify(host)
        DpiStrategySelector.recordResult(
            strategy = strat,
            success = true,
            transport = transport,
            category = category,
            latencyMs = latencyMs,
            host = host,
            quality = quality
        )
    }

    fun markFailure(
        strat: BypassStrategy, 
        transport: TransportType,
        host: String, 
        latencyMs: Long = 0,
        reason: FailureReason? = null,
        quality: ObservationQuality
    ) {
        val category = HostClassifier.classify(host)
        DpiStrategySelector.recordResult(
            strategy = strat,
            success = false,
            transport = transport,
            category = category,
            reason = reason,
            latencyMs = latencyMs,
            host = host,
            quality = quality
        )
    }

    fun recordStrategyResult(
        strategy: BypassStrategy,
        success: Boolean,
        transport: TransportType,
        host: String?,
        latencyMs: Long = 0,
        quality: ObservationQuality,
        reason: FailureReason? = null
    ) {
        if (success) {
            markSuccess(strategy, transport, host ?: "unknown", latencyMs, quality)
        } else {
            markFailure(strategy, transport, host ?: "unknown", latencyMs, reason, quality)
        }
    }



    fun enterPanicMode() {
        BypassConfig.setPanicMode(true)
    }

    fun getRecommendedFragSize(transport: TransportType = TransportType.TCP): Int {
        val intensity = BypassConfig.getIntensityForTransport(transport)
        val rttKey = "${NetworkProfileManager.currentProfile.value.id}|$transport"
        val history = rttHistory[rttKey]?.let { synchronized(it) { it.toList() } } ?: emptyList()
        val avgRtt = if (history.isNotEmpty()) history.average() else 100.0

        val baseSize = when {
            intensity > 80 -> 10
            intensity > 50 -> 40
            intensity > 20 -> 100
            else -> 500
        }
        
        val adjustedSize = if (avgRtt > 300.0 && baseSize < 100) {
            baseSize * 2 
        } else if (avgRtt < 50.0 && intensity > 50) {
            (baseSize * 0.5).toInt().coerceAtLeast(5)
        } else {
            baseSize
        }
        
        return adjustedSize
    }

    fun getRecommendedDelay(transport: TransportType): Long {
        val intensity = BypassConfig.getIntensityForTransport(transport)
        if (intensity < 10) return 0L
        
        val key = "${NetworkProfileManager.currentProfile.value.id}|$transport"
        val history = rttHistory[key]?.let { synchronized(it) { it.toList() } } ?: emptyList()
        val (avgRtt, jitter) = if (history.size > 2) {
            val avg = history.average()
            val diffs = history.zipWithNext { a, b -> Math.abs(a - b) }.average()
            avg to diffs
        } else {
            100.0 to 10.0
        }
        
        if (avgRtt > 400.0) return 5L
        
        val factor = (intensity / 100.0)
        var computed = (jitter * factor * 1.5).toLong()
        
        if (avgRtt < 50.0 && intensity > 50) {
            computed += 20L
        }
        
        return computed.coerceIn(5L, 100L)
    }

    fun triggerRecalibration(transport: TransportType) {
        RuntimeCoordinator.requestGlobalStrategyRotation(transport, "Trigger Recalibration", HostCategory.OTHER)
    }
    

    fun recordEvent(type: DpiType, transport: TransportType) {
        DpiAnalyzer.recordEvent(type, transport)
    }

}
