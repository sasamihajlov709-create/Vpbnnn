import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'r') as f:
    content = f.read()

# We will just write a new DpiEngine.kt from scratch containing the essential logic, removing the legacy maps.
new_content = """package com.aistudio.pinkproxy.fresh

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
        appContext?.let { DpiStorage.saveProfileScores(it, NetworkProfileManager.getCurrentProfile().id) }
        appContext = null
    }

    private fun switchNetworkProfile(oldProfile: NetworkProfile, newProfile: NetworkProfile, context: Context?) {
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
        consecutiveFailures[strat]?.set(0)
        consecutiveFailuresByHost[host]?.set(0)
        circuitBreakers.remove(strat)

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
        quality: ObservationQuality = ObservationQuality.CONNECT_ONLY,
        requestedStrategy: BypassStrategy? = null,
        effectiveStrategy: BypassStrategy? = null
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
            quality = quality,
            requestedStrategy = requestedStrategy,
            effectiveStrategy = effectiveStrategy
        )
    }

    private fun initStrategyChains() {
        StrategyEscalationMatrix.initializeChains(strategyChains)
    }

    fun enterPanicMode() {
        if (BypassConfig.isPanicMode) return
        BypassConfig.setPanicMode(true)
        Log.e("DpiEngine", "ENTERING PANIC MODE")
        scope.launch {
            delay(TimeUnit.MINUTES.toMillis(15))
            BypassConfig.setPanicMode(false)
        }
    }

    fun boostStrategyFamily(family: StrategyFamily, host: String?) {
        // Obsolete globally. Left empty or implement proper context-based boost.
    }

    fun boostStrategyFamilyForCategory(family: StrategyFamily, category: HostCategory) {
        // Obsolete
    }

    fun boostStrategyFamilyGlobally(family: StrategyFamily) {
        // Obsolete
    }

    fun pruneStrategies() {
        // Obsolete without global maps
    }

    fun getRecommendedFragSize(): Int {
        val intensity = ProxyStats.censorshipIntensity.value
        return when {
            intensity > 95 -> 1
            intensity > 85 -> 2
            intensity > 70 -> 3
            else -> 12
        }
    }

    fun getRecommendedDelay(): Long {
        val intensity = ProxyStats.censorshipIntensity.value
        return when {
            intensity > 95 -> 200L
            intensity > 85 -> 100L
            intensity > 70 -> 40L
            else -> 4L
        }
    }

    suspend fun triggerMicroProbe(host: String, category: HostCategory) {
        val probes = BypassStrategy.entries.filter { 
            it.group == StrategyGroup.EXTREME && StrategyExecutionRegistry.isExecutorSupported(it, TransportType.TCP)
        }.shuffled().take(3)
        
        val resolved = try { 
            RobustResolver.resolve(host) 
        } catch (e: Exception) {
            emptyList()
        }
        if (resolved.isEmpty()) return
        val addr = resolved.first()

        for (strat in probes) {
            try {
                val ok = withTimeoutOrNull(3000) {
                    val s = java.net.Socket()
                    var executedStrategy = strat
                    try {
                        BypassConfig.activeVpnService?.protect(s)
                        s.connect(java.net.InetSocketAddress(addr, 443), 1500)
                        val out = s.getOutputStream()
                        val fake = FakePacketHelper.buildRealisticTlsHello(host)
                        
                        val config = BypassConfig.getSessionConfig(host, strat, 50, TransportType.TCP)
                        executedStrategy = config.strategy
                        BypassConfig.applyBypass(s, out, fake, fake.size, config, host)
                        s.soTimeout = 1500
                        val headerBuf = ByteArray(5)
                        val readLen = s.getInputStream().read(headerBuf)
                        val isTlsServerHello = readLen >= 5 && headerBuf[0] == 0x16.toByte() && headerBuf[1] == 0x03.toByte()

                        if (isTlsServerHello) {
                            DpiStrategySelector.recordResult(
                                executedStrategy, 
                                true, 
                                transport = TransportType.TCP,
                                category = category, 
                                host = host,
                                quality = ObservationQuality.TLS_RECORD_RECEIVED
                            )
                            return@withTimeoutOrNull true
                        } else {
                            DpiStrategySelector.recordResult(
                                executedStrategy,
                                false,
                                transport = TransportType.TCP,
                                category = category,
                                reason = FailureReason.CENSORSHIP_STALL,
                                host = host,
                                quality = ObservationQuality.CONNECT_ONLY
                            )
                        }
                        false
                    } catch (e: Exception) {
                        DpiStrategySelector.recordResult(
                            executedStrategy,
                            false,
                            transport = TransportType.TCP,
                            category = category,
                            reason = FailureReason.TCP_RESET,
                            host = host,
                            quality = ObservationQuality.CONNECT_ONLY
                        )
                        false 
                    } finally { 
                        try { s.close() } catch (e: Exception) {} 
                    }
                }
                if (ok == true) return
            } catch (e: Exception) {
            }
            delay(200)
        }
    }
    
    // Delegation methods for backward compatibility
    fun getBestStrategy(category: HostCategory, host: String? = null, transport: TransportType = TransportType.TCP) = DpiStrategySelector.getBestStrategy(category, host, transport)
    fun getBestExtremeStrategy(host: String? = null, transport: TransportType = TransportType.TCP) = DpiStrategySelector.getBestExtremeStrategy(host, transport)
    fun recordResult(
        strategy: BypassStrategy, 
        success: Boolean, 
        transport: TransportType,
        category: HostCategory = HostCategory.OTHER, 
        reason: FailureReason? = null, 
        latencyMs: Long = 0, 
        host: String? = null,
        quality: ObservationQuality = if (success) ObservationQuality.APPLICATION_DATA_EXCHANGED else ObservationQuality.CONNECT_ONLY,
        requestedStrategy: BypassStrategy? = null,
        effectiveStrategy: BypassStrategy? = null
    ) = DpiStrategySelector.recordResult(
        strategy = strategy,
        success = success,
        transport = transport,
        category = category,
        reason = reason,
        latencyMs = latencyMs,
        host = host,
        quality = quality,
        requestedStrategy = requestedStrategy,
        effectiveStrategy = effectiveStrategy
    )

    fun triggerRecalibration() {
        resetStrategyScoresForNetworkChange()
        lastGlobalReset = System.currentTimeMillis()
    }
    fun recordEvent(type: DpiType) = DpiAnalyzer.recordEvent(type)
    fun getCensorshipFingerprint() = DpiAnalyzer.getCensorshipFingerprint()
}
"""

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'w') as f:
    f.write(new_content)
