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
    
    val successHistory = ConcurrentHashMap<BypassStrategy, AtomicInteger>()
    val failureHistory = ConcurrentHashMap<BypassStrategy, AtomicInteger>()
    val weightedSuccessHistory = ConcurrentHashMap<BypassStrategy, AtomicLong>()
    val categorySuccessHistory = ConcurrentHashMap<HostCategory, ConcurrentHashMap<BypassStrategy, AtomicInteger>>()
    val categoryFailureHistory = ConcurrentHashMap<HostCategory, ConcurrentHashMap<BypassStrategy, AtomicInteger>>()
    val categoryWeightedSuccessHistory = ConcurrentHashMap<HostCategory, ConcurrentHashMap<BypassStrategy, AtomicLong>>()
    val eventHistory = ConcurrentHashMap<DpiType, AtomicInteger>()
    
    private val _currentDpiLevel = MutableStateFlow(0)
    val currentDpiLevel = _currentDpiLevel.asStateFlow()

    val strategyScores = ConcurrentHashMap<HostCategory, ConcurrentHashMap<BypassStrategy, AtomicInteger>>().apply {
        HostCategory.entries.forEach { cat ->
            val catScores = ConcurrentHashMap<BypassStrategy, AtomicInteger>()
            BypassStrategy.entries.forEach { strat -> catScores[strat] = AtomicInteger(100) }
            put(cat, catScores)
        }
    }
    
    val strategyLatency = ConcurrentHashMap<BypassStrategy, AtomicLong>()
    val circuitBreakers = ConcurrentHashMap<BypassStrategy, Long>()
    val consecutiveFailures = ConcurrentHashMap<BypassStrategy, AtomicInteger>()
    val consecutiveFailuresByHost = ConcurrentHashMap<String, AtomicInteger>()
    val hostStrategyBlacklist = ConcurrentHashMap<String, ConcurrentHashMap<BypassStrategy, Long>>()
    val rttHistory = ConcurrentHashMap<HostCategory, MutableList<Long>>()
    
    val globalPenalties = ConcurrentHashMap<BypassStrategy, AtomicInteger>()
    val globalBoosts = ConcurrentHashMap<BypassStrategy, AtomicInteger>()
    val strategyMaturity = ConcurrentHashMap<BypassStrategy, AtomicInteger>()
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
    val strategyChains = ConcurrentHashMap<BypassStrategy, BypassStrategy>()

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
            var saveCounter = 0
            while (isActive) {
                delay(30000)
                try {
                    DpiAnalyzer.analyzeAndAdjust()
                    DpiAnalyzer.checkGlobalStall()
                    decayPenaltiesAndRecover()
                    saveCounter++
                    if (saveCounter >= 4) { // Save every 2 minutes
                        saveCounter = 0
                        appContext?.let { DpiStorage.saveScores(it) }
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.e("DpiEngine", "Optimizer analysis error: ${e.message}", e)
                }
            }
        }
    }

    fun decayPenaltiesAndRecover() {
        globalPenalties.values.forEach { p -> p.updateAndGet { (it * 0.85).toInt() } }
        globalBoosts.values.forEach { b -> b.updateAndGet { (it * 0.9).toInt() } }
        val now = System.currentTimeMillis()
        circuitBreakers.entries.removeIf { it.value < now }
        hostStrategyBlacklist.values.forEach { map -> map.entries.removeIf { it.value < now } }
        DpiAnalyzer.decayEventHistory()
    }

    fun stop() {
        NetworkProfileManager.removeListener(profileChangeListener)
        appContext?.let { ctx ->
            try {
                DpiStorage.saveScores(ctx, synchronous = true)
            } catch (e: Exception) {
                Log.w("DpiEngine", "Failed to save scores on stop: ${e.message}")
            }
        }
        optimizerJob?.cancel()
        optimizerJob = null
        microProbeJob?.cancel()
        microProbeJob = null
    }
    
    fun clearCircuitBreakers() {
        circuitBreakers.clear()
        consecutiveFailures.clear()
        consecutiveFailuresByHost.clear()
    }

    fun switchNetworkProfile(oldProfile: NetworkProfile, newProfile: NetworkProfile, context: Context?) {
        val ctx = context ?: appContext
        if (ctx != null && oldProfile.id.isNotBlank() && oldProfile != NetworkProfile.UNKNOWN) {
            try {
                DpiStorage.saveProfileScores(ctx, oldProfile.id, synchronous = true)
            } catch (e: Exception) {
                Log.w("DpiEngine", "Failed to save profile scores for ${oldProfile.id}: ${e.message}")
            }
        }

        clearCircuitBreakers()
        globalPenalties.clear()
        globalBoosts.clear()
        strategyLatency.clear()

        if (ctx != null && newProfile.id.isNotBlank() && newProfile != NetworkProfile.UNKNOWN) {
            try {
                DpiStorage.loadProfileScores(ctx, newProfile.id)
                Log.i("DpiEngine", "Loaded learned DPI scores for profile ${newProfile.displayName} (${newProfile.id})")
            } catch (e: Exception) {
                Log.e("DpiEngine", "Failed to load profile scores for ${newProfile.id}: ${e.message}")
                resetStrategyScoresForNetworkChange()
            }
        } else {
            resetStrategyScoresForNetworkChange()
        }
    }

    fun resetStrategyScoresForNetworkChange() {
        strategyScores.forEach { (_, scores) ->
            scores.forEach { (_, score) -> score.set(100) }
        }
        globalPenalties.clear()
        globalBoosts.clear()
        strategyLatency.clear()
        successHistory.clear()
        failureHistory.clear()
        weightedSuccessHistory.clear()
        categorySuccessHistory.clear()
        categoryFailureHistory.clear()
        categoryWeightedSuccessHistory.clear()
        eventHistory.clear()
        strategyMaturity.clear()
        circuitBreakers.clear()
        consecutiveFailures.clear()
        consecutiveFailuresByHost.clear()
        hostSpecificMemory.clear()
        contextualHostMemory.clear()
        hostStrategyBlacklist.clear()
    }
    
    fun isBlacklisted(strat: BypassStrategy, host: String? = null): Boolean {
        val now = System.currentTimeMillis()
        if ((circuitBreakers[strat] ?: 0L) >= now) return true
        if (host != null) {
            val bl = hostStrategyBlacklist[host]?.get(strat) ?: 0L
            if (bl >= now) return true
        }
        return false
    }

    fun selectStrategy(host: String? = null, category: HostCategory = HostCategory.OTHER, transport: TransportType = TransportType.TCP): BypassStrategy =
        DpiStrategySelector.getBestStrategy(category, host, transport)

    fun getFallbackStrategy(
        strat: BypassStrategy,
        reason: FailureReason? = null,
        transport: TransportType = TransportType.TCP,
        host: String? = null,
        category: HostCategory? = null
    ): BypassStrategy? = DpiStrategySelector.getFallbackStrategy(strat, transport, reason, host, category)

    fun getDiverseFallback(failed: BypassStrategy? = null, category: HostCategory? = null, transport: TransportType = TransportType.TCP): BypassStrategy = DpiStrategySelector.getDiverseFallback(failed, category, transport)
    
    fun updateTestingStrategies(list: List<BypassStrategy>) {
        BypassConfig.updateTestingStrategies(list)
    }
    
    fun recordStrategyResult(
        host: String,
        strat: BypassStrategy,
        success: Boolean,
        latencyMs: Long = 0,
        reason: FailureReason? = null,
        quality: ObservationQuality = ObservationQuality.FULL_DATA_TRANSFER,
        requestedStrategy: BypassStrategy? = null,
        effectiveStrategy: BypassStrategy? = null
    ) {
        val category = HostClassifier.classify(host)
        DpiStrategySelector.recordResult(
            strategy = strat,
            success = success,
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
        if (!host.isNullOrBlank()) {
            val category = HostClassifier.classify(host)
            boostStrategyFamilyForCategory(family, category)
        } else {
            boostStrategyFamilyGlobally(family)
        }
    }

    fun boostStrategyFamilyForCategory(family: StrategyFamily, category: HostCategory) {
        strategyScores[category]?.forEach { (strat, score) ->
            if (strat.family == family) {
                val boost = if (strat.group == StrategyGroup.EXTREME) 60 else 30
                score.addAndGet(boost)
            }
        }
    }

    fun boostStrategyFamilyGlobally(family: StrategyFamily) {
        strategyScores.forEach { (_, scores) ->
            scores.forEach { (strat, score) ->
                if (strat.family == family) {
                    val boost = if (strat.group == StrategyGroup.EXTREME) 60 else 30
                    score.addAndGet(boost)
                }
            }
        }
    }

    fun pruneStrategies() {
        strategyScores.forEach { (_, scores) ->
            scores.forEach { (strat, score) ->
                if (score.get() < 30) {
                    circuitBreakers[strat] = System.currentTimeMillis() + 300000 
                }
            }
        }
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
        } catch (e: java.net.UnknownHostException) {
            Log.v("DpiEngine", "MicroProbe DNS failed for $host: ${e.message}")
            emptyList() 
        } catch (e: Exception) {
            Log.v("DpiEngine", "MicroProbe DNS unexpected error for $host: ${e.message}")
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
                                category, 
                                host = host,
                                quality = ObservationQuality.TLS_RECORD_RECEIVED
                            )
                            return@withTimeoutOrNull true
                        } else {
                            DpiStrategySelector.recordResult(
                                executedStrategy,
                                false,
                                category,
                                reason = FailureReason.CENSORSHIP_STALL,
                                host = host,
                                quality = ObservationQuality.CONNECT_ONLY
                            )
                        }
                        false
                    } catch (e: Exception) {
                        Log.v("DpiEngine", "Probe $executedStrategy failed: ${e.message}")
                        DpiStrategySelector.recordResult(
                            executedStrategy,
                            false,
                            category,
                            reason = FailureReason.TCP_RESET,
                            host = host,
                            quality = ObservationQuality.CONNECT_ONLY
                        )
                        false 
                    } catch (e: Throwable) {
                        false
                    } finally { 
                        try { s.close() } catch (e: java.io.IOException) {} 
                    }
                }
                if (ok == true) return
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.v("DpiEngine", "Probe execution error: ${e.message}")
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
        category: HostCategory = HostCategory.OTHER, 
        reason: FailureReason? = null, 
        latencyMs: Long = 0, 
        host: String? = null,
        quality: ObservationQuality = ObservationQuality.FULL_DATA_TRANSFER,
        requestedStrategy: BypassStrategy? = null,
        effectiveStrategy: BypassStrategy? = null
    ) = DpiStrategySelector.recordResult(
        strategy = strategy,
        success = success,
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
