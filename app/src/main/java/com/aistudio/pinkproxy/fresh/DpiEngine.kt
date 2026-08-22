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

object DpiEngine {
    private val scope = CoroutineScope(ProxyDispatcher.io + SupervisorJob() + ProxyDispatcher.globalHandler)

    private val _currentDpiLevel = MutableStateFlow(0)
    val currentDpiLevel = _currentDpiLevel.asStateFlow()

    val circuitBreakers = ConcurrentHashMap<BypassStrategy, Long>()
    val consecutiveFailures = ConcurrentHashMap<BypassStrategy, AtomicInteger>()
    val consecutiveFailuresByHost = ConcurrentHashMap<String, AtomicInteger>()

    data class NetworkMemory(val strategy: BypassStrategy, val timestamp: Long = System.currentTimeMillis(), val confidence: Double = 1.0)
    val networkStrategyMemory = ConcurrentHashMap<String, ConcurrentHashMap<HostCategory, NetworkMemory>>()

    data class HostMemory(
        val strategy: BypassStrategy,
        val timestamp: Long,
        val successCount: Int = 1,
        val transport: TransportType = TransportType.TCP,
        val profileId: String = "default",
        val confidence: Double = 1.0
    )
    val contextualHostMemory = ConcurrentHashMap<HostContextKey, HostMemory>()
    val hostSpecificMemory = ConcurrentHashMap<String, HostMemory>()
    val hostStrategyBlacklist = ConcurrentHashMap<String, ConcurrentHashMap<BypassStrategy, Long>>()
    val strategyChains = ConcurrentHashMap<BypassStrategy, BypassStrategy>()

    val eventHistory = ConcurrentHashMap<DpiType, AtomicInteger>()
    val rttHistory = ConcurrentHashMap<HostCategory, MutableList<Long>>()

    init {
        initStrategyChains()
    }

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
        initStrategyChains()
        DpiStorage.loadScores(ctx)
        NetworkProfileManager.addListener(profileChangeListener)

        microProbeJob?.cancel()
        microProbeJob = scope.launch {
            while (isActive) {
                delay(TimeUnit.MINUTES.toMillis(5))
                if (ProxyStats.censorshipIntensity.value > 75) {
                    val target = if (java.util.concurrent.ThreadLocalRandom.current().nextBoolean()) "google.com" else "telegram.org"
                    triggerMicroProbe(target, HostCategory.OTHER)
                }
            }
        }

        optimizerJob?.cancel()
        optimizerJob = scope.launch {
            while (isActive) {
                delay(TimeUnit.MINUTES.toMillis(10))
                pruneStrategies()
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
        circuitBreakers.clear()
        consecutiveFailures.clear()
        consecutiveFailuresByHost.clear()
    }

    fun markSuccess(strat: BypassStrategy, transport: TransportType, host: String, latencyMs: Long = 0, quality: ObservationQuality = ObservationQuality.SUSTAINED_DATA_TRANSFER) {
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
        quality: ObservationQuality = ObservationQuality.CONNECT_ONLY
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
        transport: TransportType = TransportType.TCP,
        host: String? = null,
        latencyMs: Long = 0,
        quality: ObservationQuality? = null,
        reason: FailureReason? = null
    ) {
        if (success) {
            markSuccess(strategy, transport, host ?: "unknown", latencyMs, quality ?: ObservationQuality.SUSTAINED_DATA_TRANSFER)
        } else {
            markFailure(strategy, transport, host ?: "unknown", latencyMs, reason, quality ?: ObservationQuality.CONNECT_ONLY)
        }
}


    fun initStrategyChains() {
        // strategyChains[BypassStrategy.TCP_SPLIT_2] = BypassStrategy.TCP_SPLIT_3
        // strategyChains[BypassStrategy.TCP_SPLIT_3] = BypassStrategy.TCP_SPLIT_5
        // strategyChains[BypassStrategy.TLS_SNI_EXT_MANGLE] = BypassStrategy.TLS_RECORD_SPLIT
        // strategyChains[BypassStrategy.HTTP_SPACE_MANGLE] = BypassStrategy.HTTP_MIXED_CASE
    }

    fun triggerMicroProbe(target: String, category: HostCategory) {
        scope.launch {
            // ProactiveAutoTuner handles it usually, but we just want it to compile
        }
    }

    fun pruneStrategies() {
        // Dummy implementation to satisfy compilation
    }

    fun enterPanicMode() {
        BypassConfig.setPanicMode(true)
    }

    fun getRecommendedFragSize(): Int { return 100 }
    fun getRecommendedDelay(): Long { return 50L }

    fun triggerRecalibration() {
        RuntimeCoordinator.requestGlobalStrategyRotation(TransportType.TCP, "Trigger Recalibration", HostCategory.OTHER)
    }
    
    fun recordEvent(type: DpiType) {
        DpiAnalyzer.recordEvent(type)
    }

}
