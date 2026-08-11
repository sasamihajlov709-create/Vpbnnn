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
    val categorySuccessHistory = ConcurrentHashMap<HostCategory, ConcurrentHashMap<BypassStrategy, AtomicInteger>>()
    val categoryFailureHistory = ConcurrentHashMap<HostCategory, ConcurrentHashMap<BypassStrategy, AtomicInteger>>()
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
    
    data class HostMemory(val strategy: BypassStrategy, val timestamp: Long)
    val hostSpecificMemory = ConcurrentHashMap<String, HostMemory>()
    val strategyChains = ConcurrentHashMap<BypassStrategy, BypassStrategy>()

    private var lastGlobalReset = System.currentTimeMillis()
    private var lastPanicTime = 0L
    val isPanicMode: StateFlow<Boolean> get() = BypassConfig.isPanicModeFlow

    private var optimizerJob: Job? = null
    private var microProbeJob: Job? = null
    private var appContext: Context? = null

    fun start(context: Context) {
        stop()
        val ctx = context.applicationContext
        appContext = ctx
        initStrategyChains()
        DpiStorage.loadScores(ctx)

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
    }

    fun stop() {
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

    fun resetStrategyScoresForNetworkChange() {
        strategyScores.forEach { (_, scores) ->
            scores.forEach { (_, score) -> score.set(100) }
        }
        globalPenalties.clear()
        globalBoosts.clear()
        strategyLatency.clear()
        successHistory.clear()
        failureHistory.clear()
        eventHistory.clear()
        strategyMaturity.clear()
        circuitBreakers.clear()
        consecutiveFailures.clear()
        consecutiveFailuresByHost.clear()
        hostSpecificMemory.clear()
        hostStrategyBlacklist.clear()
    }
    
    fun getFallbackStrategy(strat: BypassStrategy): BypassStrategy? = DpiStrategySelector.getFallbackStrategy(strat)
    fun getDiverseFallback(failed: BypassStrategy? = null, category: HostCategory? = null, transport: TransportType = TransportType.TCP): BypassStrategy = DpiStrategySelector.getDiverseFallback(failed, category, transport)
    
    fun updateTestingStrategies(list: List<BypassStrategy>) {
        BypassConfig.updateTestingStrategies(list)
    }
    
    fun recordStrategyResult(host: String, strat: BypassStrategy, success: Boolean, latencyMs: Long = 0) {
        val category = HostClassifier.classify(host)
        DpiStrategySelector.recordResult(strat, success, category, latencyMs = latencyMs, host = host)
    }

    private fun initStrategyChains() {
        strategyChains[BypassStrategy.SNI_SPLIT] = BypassStrategy.TLS_SNI_FRAGMENT
        strategyChains[BypassStrategy.TLS_SNI_FRAGMENT] = BypassStrategy.TLS_APP_DATA_SPLIT
        strategyChains[BypassStrategy.TLS_APP_DATA_SPLIT] = BypassStrategy.BYEBYEDPI_HYBRID
        strategyChains[BypassStrategy.BYEBYEDPI_HYBRID] = BypassStrategy.TCP_SEGMENT_OVERLAP
        strategyChains[BypassStrategy.TCP_SEGMENT_OVERLAP] = BypassStrategy.TCP_REARRANGE_CHUNKS
        strategyChains[BypassStrategy.TCP_REARRANGE_CHUNKS] = BypassStrategy.TCP_DATA_DESYNC_OVERLAP
        strategyChains[BypassStrategy.TCP_DATA_DESYNC_OVERLAP] = BypassStrategy.TCP_TRIPLE_DESYNC
        strategyChains[BypassStrategy.TCP_TRIPLE_DESYNC] = BypassStrategy.TCP_FAKE_FIN
        strategyChains[BypassStrategy.TCP_FAKE_FIN] = BypassStrategy.TCP_COMBINED_NUCLEAR
        
        strategyChains[BypassStrategy.TCP_FOOL_DPI] = BypassStrategy.ZAPRET_EXTREME
        strategyChains[BypassStrategy.ZAPRET_EXTREME] = BypassStrategy.TCP_COMBINED_NUCLEAR
        
        strategyChains[BypassStrategy.UDP_NOISE_CHAOS] = BypassStrategy.UDP_BURST_CHAOS
        strategyChains[BypassStrategy.UDP_BURST_CHAOS] = BypassStrategy.UDP_COMBINED_NUCLEAR
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
        val category = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
        strategyScores[category]?.forEach { (strat, score) ->
            if (strat.family == family) {
                val boost = if (strat.group == StrategyGroup.EXTREME) 60 else 30
                score.addAndGet(boost)
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
        val probes = BypassStrategy.entries.filter { it.group == StrategyGroup.EXTREME }.shuffled().take(3)
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
                    try {
                        BypassConfig.activeVpnService?.protect(s)
                        s.connect(java.net.InetSocketAddress(addr, 443), 1500)
                        val out = s.getOutputStream()
                        val fake = FakePacketHelper.buildRealisticTlsHello(host)
                        val config = BypassConfig.getSessionConfig(host, strat, 50)
                        BypassConfig.applyBypass(s, out, fake, fake.size, config, host)
                        s.soTimeout = 1500
                        val headerBuf = ByteArray(5)
                        val readLen = s.getInputStream().read(headerBuf)
                        val success = readLen >= 5 && headerBuf[0] == 0x16.toByte() && headerBuf[1] == 0x03.toByte()
                        if (success) {
                            DpiStrategySelector.recordResult(config.strategy, true, category, host = host)
                            return@withTimeoutOrNull true
                        }
                        false
                    } catch (e: Exception) {
                        Log.v("DpiEngine", "Probe $strat failed: ${e.message}")
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
    fun recordResult(strategy: BypassStrategy, success: Boolean, category: HostCategory = HostCategory.OTHER, reason: FailureReason? = null, latencyMs: Long = 0, host: String? = null) = 
        DpiStrategySelector.recordResult(strategy, success, category, reason, latencyMs, host)
    fun triggerRecalibration() {
        resetStrategyScoresForNetworkChange()
        lastGlobalReset = System.currentTimeMillis()
    }

    fun recordEvent(type: DpiType) = DpiAnalyzer.recordEvent(type)
    fun getCensorshipFingerprint() = DpiAnalyzer.getCensorshipFingerprint()
}
