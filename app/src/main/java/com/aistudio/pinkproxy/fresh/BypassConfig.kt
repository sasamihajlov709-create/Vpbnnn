package com.aistudio.pinkproxy.fresh

import android.content.Context
import android.net.VpnService
import android.util.Log
import androidx.core.content.edit
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.CancellationException as CoroutineCancellationException
import java.net.*
import java.nio.ByteBuffer
import java.util.*
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.io.*

object BypassConfig {
    private val _strategy = MutableStateFlow(BypassStrategy.SNI_SPLIT)
    val strategy: StateFlow<BypassStrategy> = _strategy.asStateFlow()
    
    private val _testingStrategies = MutableStateFlow<List<BypassStrategy>>(
        listOf(
            BypassStrategy.SNI_SPLIT,
            BypassStrategy.FAKE_PACKET,
            BypassStrategy.TCP_OOB_DESYNC,
            BypassStrategy.BYEBYEDPI_HYBRID,
            BypassStrategy.ZAPRET_EXTREME
        )
    )
    val testingStrategies: StateFlow<List<BypassStrategy>> = _testingStrategies.asStateFlow()

    private val _currentTtl = MutableStateFlow(64)
    val currentTtl: StateFlow<Int> = _currentTtl.asStateFlow()

    fun setTtl(ttl: Int) {
        _currentTtl.value = ttl
    }

    fun updateTestingStrategies(strategies: List<BypassStrategy>) {
        if (strategies.isNotEmpty()) {
            _testingStrategies.value = strategies.distinct().take(6)
        }
    }
    
    private val _censorshipLevel = ProxyStats.censorshipIntensity
    val censorshipLevel: StateFlow<Int> = _censorshipLevel

    private val _currentNetworkType = MutableStateFlow(NetworkType.UNKNOWN)
    val currentNetworkType: StateFlow<NetworkType> = _currentNetworkType.asStateFlow()

    private val hostBlacklist = ConcurrentHashMap<String, ConcurrentHashMap<BypassStrategy, Long>>()
    class StratStats(val successes: AtomicLong = AtomicLong(), val failures: AtomicLong = AtomicLong(), val totalRtt: AtomicLong = AtomicLong())
    private val strategyStats = ConcurrentHashMap<BypassStrategy, StratStats>()

    private val _currentRttMs = MutableStateFlow(50L)
    val currentRttMs: StateFlow<Long> = _currentRttMs.asStateFlow()

    private val _currentFragSizeState = MutableStateFlow(1)
    val currentFragSizeState: StateFlow<Int> = _currentFragSizeState.asStateFlow()

    private val _isPanicModeFlow = MutableStateFlow(false)
    val isPanicModeFlow: StateFlow<Boolean> = _isPanicModeFlow.asStateFlow()

    private val _currentMtu = MutableStateFlow(1400)
    val currentMtu: StateFlow<Int> = _currentMtu.asStateFlow()

    private val _isChargingFlow = MutableStateFlow(true)
    val isChargingFlow: StateFlow<Boolean> = _isChargingFlow.asStateFlow()

    @Volatile var isAutoTuning = true
    @Volatile var frag1 = 1
    @Volatile var frag2 = 5
    @Volatile var frag3 = 2
    @Volatile var delay1 = 20L
    @Volatile var delay2 = 100L
    @Volatile var fakeTtl = 0
    @Volatile var isDiagnosticMode = false
    @Volatile var blockQuic = false
    @Volatile var isCharging = true
    @Volatile var preferIpv6 = false

    @Volatile var tcpSplitPosValue = 2
    @Volatile var tcpDelayValue = 2L
    @Volatile var udpTtlValue = 3
    @Volatile var fakePacketSizeValue = 64

    // Session Stickiness with TTL
    private val hostStrategyMemory = ConcurrentHashMap<String, Pair<BypassStrategy, Long>>()
    private val SESSION_TTL = 30 * 60 * 1000L // 30 minutes
    
    private val censorHeuristic = ConcurrentHashMap<String, Int>()
    private val hostLockTime = ConcurrentHashMap<String, Long>()

    fun isHostProbablyCensored(host: String): Boolean {
        if (hostLockTime[host]?.let { System.currentTimeMillis() - it < 300_000 } == true) return true
        
        val category = HostClassifier.classify(host)
        val categoryRisk = when(category) {
            HostCategory.SOCIAL, HostCategory.MESSENGER, HostCategory.STREAMING, HostCategory.AI -> true
            else -> false
        }
        
        val intensity = ProxyStats.censorshipIntensity.value
        return (censorHeuristic[host] ?: 0) >= 2 || (categoryRisk && intensity > 60)
    }

    val isPanicMode: Boolean get() = _isPanicModeFlow.value
    fun setPanicMode(enabled: Boolean) {
        _isPanicModeFlow.value = enabled
    }

    init {
        BypassStrategy.entries.forEach {
            strategyStats[it] = StratStats()
        }
        ProxyDispatcher.mainScope.launch(ProxyDispatcher.io) {
            while (kotlinx.coroutines.currentCoroutineContext()[kotlinx.coroutines.Job]?.isActive == true) {
                kotlinx.coroutines.delay(10 * 60 * 1000L) // 10 minutes
                val now = System.currentTimeMillis()
                
                // Cleanup memory
                val toRemove = hostStrategyMemory.filterValues { it.second < now }.keys
                toRemove.forEach { hostStrategyMemory.remove(it) }
                
                if (censorHeuristic.size > 2000) {
                    val toKeep = censorHeuristic.entries.sortedByDescending { it.value }.take(1000).associate { it.key to it.value }
                    censorHeuristic.clear()
                    censorHeuristic.putAll(toKeep)
                }
                
                val toRemoveLock = hostLockTime.filterValues { now - it > 300_000 }.keys
                toRemoveLock.forEach { hostLockTime.remove(it) }
            }
        }
    }

    fun setMtu(mtu: Int) {
        val old = _currentMtu.value
        val new = mtu.coerceIn(576, 1500)
        if (old != new) {
            _currentMtu.value = new
            Log.i("BypassConfig", "MTU changed from $old to $new. Triggering VPN restart.")
        }
    }

    fun updateNetworkType(type: NetworkType) {
        if (_currentNetworkType.value != type) {
            _currentNetworkType.value = type
            Log.i("BypassConfig", "Network type updated: $type. Clearing session memory.")
            hostStrategyMemory.clear()
            DpiEngine.clearCircuitBreakers()
            DpiEngine.resetStrategyScoresForNetworkChange()
        }
    }

    fun getNetworkType() = _currentNetworkType.value

    private val lastCleanup = AtomicLong(0)
    private fun ensureMemoryEfficiency() {
        val now = System.currentTimeMillis()
        if (now - lastCleanup.get() < 60000L) return
        lastCleanup.set(now)
        
        if (hostStrategyMemory.size > 2000) {
            val sorted = hostStrategyMemory.entries.sortedBy { it.value.second }
            val toRemove = sorted.take(500)
            toRemove.forEach { hostStrategyMemory.remove(it.key) }
        }
        
        if (hostLockTime.size > 2000) {
            hostLockTime.entries.removeIf { now - it.value > 300_000 }
            if (hostLockTime.size > 2000) {
                hostLockTime.clear()
            }
        }
        
        if (censorHeuristic.size > 2000) {
            censorHeuristic.clear()
        }
        
        hostBlacklist.forEach { (_, map) ->
            map.entries.removeIf { now - it.value > 600_000 }
        }
        hostBlacklist.entries.removeIf { it.value.isEmpty() }
    }

    fun loadTuningSettings(context: Context) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
        isAutoTuning = prefs.getBoolean("is_auto_tuning", true)
        blockQuic = prefs.getBoolean("block_quic", false)
        isDiagnosticMode = prefs.getBoolean("is_diagnostic_mode", false)
        frag1 = prefs.getInt("frag1", 1)
        frag2 = prefs.getInt("frag2", 5)
        frag3 = prefs.getInt("frag3", 2)
        delay1 = prefs.getLong("delay1", 20L)
        delay2 = prefs.getLong("delay2", 100L)
        fakeTtl = prefs.getInt("fakeTtl", 0)
        val savedStrat = prefs.getString("global_strategy", BypassStrategy.SNI_SPLIT.name)
        _strategy.value = try {
            BypassStrategy.valueOf(savedStrat ?: BypassStrategy.SNI_SPLIT.name)
        } catch (e: Exception) {
            BypassStrategy.SNI_SPLIT
        }
        
        prefs.getString("censor_heuristic_data", null)?.let { data ->
            data.split(";").forEach { entry ->
                val parts = entry.split(",")
                if (parts.size == 2) {
                    try {
                        censorHeuristic[parts[0]] = parts[1].toInt()
                    } catch (e: Throwable) {}
                }
            }
        }
    }

    fun saveTuningSettings(context: Context) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
        prefs.edit {
            putBoolean("is_auto_tuning", isAutoTuning)
            putBoolean("block_quic", blockQuic)
            putBoolean("is_diagnostic_mode", isDiagnosticMode)
            putInt("frag1", frag1)
            putInt("frag2", frag2)
            putInt("frag3", frag3)
            putLong("delay1", delay1)
            putLong("delay2", delay2)
            putInt("fakeTtl", fakeTtl)
            putString("global_strategy", _strategy.value.name)
            
            val heuristicStr = censorHeuristic.entries.joinToString(";") { "${it.key},${it.value}" }
            putString("censor_heuristic_data", heuristicStr)
        }
    }

    fun getBestStrategyForHost(host: String): BypassStrategy {
        ensureMemoryEfficiency()
        if (!isAutoTuning) return _strategy.value
        
        val cat = HostClassifier.classify(host)
        val now = System.currentTimeMillis()

        hostStrategyMemory[host]?.let { (remembered, expiry) ->
            if (now < expiry) return remembered
            hostStrategyMemory.remove(host)
        }

        val best = DpiEngine.getBestStrategy(cat, host)
        hostStrategyMemory[host] = best to (now + SESSION_TTL)
        return best
    }

    private val lastStrategies = Collections.synchronizedList(LinkedList<BypassStrategy>())
    
    fun rotateGlobalStrategy() {
        val fingerprint = DpiEngine.getCensorshipFingerprint()
        val intensity = ProxyStats.censorshipIntensity.value
        
        val best = BypassStrategy.entries
            .filter { it != BypassStrategy.DIRECT && it != _strategy.value && !lastStrategies.contains(it) }
            .maxByOrNull { strat ->
                var baseScore = DpiEngine.getAverageScore(strat)
                if (fingerprint.rstRate > 0.4 && strat.family == StrategyFamily.TCP) {
                    if (strat == BypassStrategy.FAKE_PACKET || strat == BypassStrategy.TCP_OOB_DESYNC) baseScore += 50
                }
                if (fingerprint.sniBlockRate > 0.4 && strat.family == StrategyFamily.TLS) {
                    if (strat == BypassStrategy.SNI_SPLIT || strat == BypassStrategy.BYEBYEDPI_HYBRID) baseScore += 50
                }
                if (intensity > 80 && strat.group == StrategyGroup.EXTREME) baseScore += 30
                baseScore
            } ?: BypassStrategy.SNI_SPLIT
        
        synchronized(lastStrategies) {
            lastStrategies.add(best)
            if (lastStrategies.size > 5) {
                lastStrategies.removeAt(0)
            }
        }
        
        _strategy.value = best
        updateTestingStrategies(synchronized(lastStrategies) { lastStrategies.toList() } + best)
        VpnRuntimeState.updateStrategy(best.name)
        ProxyStats.logRecovery("Strategy rotated: ${best.name}")
    }

    private var optimizerJob: Job? = null
    fun startAutonomousOptimizer(scope: CoroutineScope, context: Context) {
        if (optimizerJob?.isActive == true) return
        optimizerJob = scope.launch {
            while (isActive) {
                try {
                    delay(30000)
                    performSelfHealing()
                    
                    val currentRate = ProxyStats.getSuccessRate()
                    if (currentRate < 60) ProxyStats.recordCensorshipEvent(true)
                    else if (currentRate > 90) ProxyStats.recordCensorshipEvent(false)

                    val intensity = ProxyStats.censorshipIntensity.value
                    if (intensity > 90 && !isPanicMode) panicOptimize()

                    val mssFailures = ProxyStats.mssFailureCount.value
                    if (mssFailures > 5 && _currentMtu.value > 1200) {
                        _currentMtu.value = (_currentMtu.value - 40).coerceAtLeast(1100)
                        ProxyStats.resetMssFailureCount()
                    }
                    
                    if (currentRate < 70) {
                        tcpSplitPosValue = (tcpSplitPosValue % 8) + 1
                        tcpDelayValue = (tcpDelayValue % 4) + 1
                        udpTtlValue = (udpTtlValue % 4) + 2
                        fakePacketSizeValue = (fakePacketSizeValue + 32) % 512 + 32
                    }
                } catch (e: CoroutineCancellationException) { 
                    throw e 
                } catch (e: Throwable) { 
                    Log.e("BypassConfig", "Optimizer error", e) 
                }
            }
        }
    }

    fun recordSuccess(strat: BypassStrategy, rtt: Long, host: String?) {
        ProxyStats.recordGlobalSuccess(rtt)
        val cat = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
        DpiEngine.recordResult(strat, true, cat, latencyMs = rtt, host = host)
        
        if (rtt > 0) {
            TrafficShaper.updateRtt(rtt)
            _currentRttMs.value = (_currentRttMs.value * 7 + rtt) / 8
            ProxyStats.updateLatency(_currentRttMs.value)
        }
        
        if (host != null) {
            censorHeuristic.remove(host)
            hostLockTime.remove(host)
            hostStrategyMemory[host] = strat to (System.currentTimeMillis() + SESSION_TTL)
        }
    }

    fun recordSuccess(strat: BypassStrategy, rtt: Long, context: Context?) = recordSuccess(strat, rtt, null as String?)

    fun recordDpiFailure(strat: BypassStrategy, host: String?, type: DpiType) {
        recordFailure(strat, host)
        ProxyStats.recordDpiEvent(type)
        
        when (type) {
            DpiType.DNS_POISONING -> {
                DnsCacheManager.clear()
                DnsOptimizer.forceRefresh()
            }
            DpiType.TCP_RESET -> DpiEngine.boostStrategyFamily(StrategyFamily.TCP, host)
            DpiType.TLS_SNI_BLOCK -> {
                DpiEngine.boostStrategyFamily(StrategyFamily.TLS, host)
                DpiEngine.boostStrategyFamily(StrategyFamily.FRAGMENTATION, host)
            }
            DpiType.CONNECTION_TIMEOUT, DpiType.BLACKHOLE -> {
                if (ProxyStats.censorshipIntensity.value > 50) {
                    _currentMtu.update { (it - 50).coerceAtLeast(1000) }
                }
                DpiEngine.boostStrategyFamily(StrategyFamily.FRAGMENTATION, host)
            }
            DpiType.UDP_BLOCK -> {
                DpiEngine.boostStrategyFamily(StrategyFamily.UDP, host)
                DpiEngine.boostStrategyFamily(StrategyFamily.QUIC, host)
            }
            else -> {}
        }
    }

    fun detectBlackhole(host: String, dataSent: Int, dataReceived: Int, duration: Long): Boolean {
        val sensitivity = if (censorHeuristic.getOrDefault(host, 0) > 2) 1500 else 3500
        if (dataSent > 0 && dataReceived == 0 && duration > sensitivity) {
            recordDpiFailure(_strategy.value, host, DpiType.BLACKHOLE)
            return true
        }
        return false
    }

    fun recordFailure(strat: BypassStrategy, host: String?, reason: FailureReason = FailureReason.UNKNOWN) {
        ProxyStats.recordCensorshipEvent(true)
        val cat = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
        DpiEngine.recordResult(strat, false, cat, reason, host = host)
        
        if (host != null) {
            val count = censorHeuristic.getOrDefault(host, 0) + 1
            censorHeuristic[host] = count
            if (count >= 5) hostLockTime[host] = System.currentTimeMillis()
            hostStrategyMemory.remove(host)
        }
    }

    fun performSelfHealing() {
        val rate = ProxyStats.getSuccessRate()
        val lockedCount = hostLockTime.filter { System.currentTimeMillis() - it.value < 300_000 }.size
        val intensity = ProxyStats.censorshipIntensity.value
        
        if ((rate < 35 || lockedCount >= 4 || intensity > 85) && !isPanicMode) {
            panicOptimize()
        } else if (rate > 80 && lockedCount == 0 && intensity < 70 && isPanicMode) {
            _isPanicModeFlow.value = false
            DpiEngine.clearCircuitBreakers()
        }
    }

    fun panicOptimize() {
        _isPanicModeFlow.value = true
        val oldMtu = _currentMtu.value
        val newMtu = when {
            oldMtu > 1300 -> 1260
            oldMtu > 1200 -> 1100
            else -> 1000
        }
        if (Math.abs(oldMtu - newMtu) < 32) {
            _currentMtu.value = oldMtu - 32
        } else {
            _currentMtu.value = newMtu
        }
        DpiEngine.clearCircuitBreakers()
        rotateGlobalStrategy()
        hostStrategyMemory.clear()
        censorHeuristic.clear() 
        frag1 = 1
        delay1 = 50
        blockQuic = true
    }

    fun getSessionConfig(host: String, strategy: BypassStrategy, rtt: Long): SessionConfig {
        val rnd = ThreadLocalRandom.current()
        val intensity = ProxyStats.censorshipIntensity.value
        val effectiveStrategy = if (_isPanicModeFlow.value && rnd.nextInt(100) < 80) DpiEngine.getBestExtremeStrategy(host) else strategy
        
        var f1 = DpiEngine.getRecommendedFragSize()
        var d1 = DpiEngine.getRecommendedDelay()
        
        if (intensity > 70) {
            f1 = (f1 / 2).coerceAtLeast(1)
            d1 = (d1 * 1.5).toLong()
        }
        
        val ttl = if (fakeTtl == 0) rnd.nextInt(3, 8) else fakeTtl
        val mss = if (intensity > 75) rnd.nextInt(512, 1000) else 1440

        return SessionConfig(
            strategy = effectiveStrategy,
            frag1 = f1,
            delay1 = d1,
            fakeTtl = ttl,
            useIPv6 = host.contains(":") || (rnd.nextInt(100) < 15 && intensity > 60),
            mss = mss
        )
    }

    fun isHostCensored(host: String): Boolean {
        val h = host.lowercase(Locale.ROOT)
        return h.contains("youtube") || h.contains("facebook") || h.contains("instagram") || h.contains("twitter") ||
               h.contains("telegram") || h.contains("discord") || h.contains("openai") || h.contains("github") ||
               h.contains("spotify") || h.contains("meduza") || h.contains("google")
    }

    private val bypassList = hashSetOf(
        ".ru", ".by", ".kz", ".ua", ".su", ".local", ".lan",
        "yandex", "vk.com", "ok.ru", "mail.ru", "gosuslugi.ru", "sberbank.ru"
    )

    fun isHostDirect(host: String): Boolean {
        val h = host.lowercase(Locale.ROOT)
        if (h == "localhost" || h == "127.0.0.1" || h == "::1") return true
        if (h.startsWith("10.") || h.startsWith("192.168.")) return true
        return bypassList.any { h.contains(it) }
    }

    fun clearScores(context: Context) {
        DpiEngine.clearCircuitBreakers()
    }
    
    fun resetCaches() {
        hostStrategyMemory.clear()
        DpiEngine.clearCircuitBreakers()
    }

    fun setStrategy(strat: BypassStrategy) {
        _strategy.value = strat
    }
    fun setGlobalStrategy(strat: BypassStrategy) = setStrategy(strat)

    fun getStrategyMetrics(): List<StrategyMetric> {
        return BypassStrategy.entries.map { strat ->
            val score = DpiEngine.getAverageScore(strat).toInt()
            val stats = strategyStats[strat] ?: StratStats()
            val s = stats.successes.get()
            val f = stats.failures.get()
            val t = stats.totalRtt.get()
            val avgRtt = if (s > 0) t / s else 0L
            StrategyMetric(strat, score, s, f, avgRtt)
        }.sortedByDescending { it.score }
    }

    object TrafficShaper {
        private var errorCounter = 0
        fun recordError() {
            errorCounter++
            if (errorCounter > 8) ProxyStats.updateCongestionWindow(-5)
            if (errorCounter > 20) {
                val currentMtu = _currentMtu.value
                if (currentMtu > 1200) {
                    _currentMtu.value = currentMtu - 50
                }
                errorCounter = 0
            }
        }
        fun updateRtt(rtt: Long) {
            if (rtt < 100) ProxyStats.updateCongestionWindow(2)
            else if (rtt > 500) ProxyStats.updateCongestionWindow(-2)
        }
    }

    @Volatile var activeVpnService: VpnService? = null

    suspend fun applyBypass(socket: Socket, output: OutputStream, data: ByteArray, length: Int, config: SessionConfig, host: String) {
        val rnd = ThreadLocalRandom.current()
        val strategy = config.strategy
        if (strategy == BypassStrategy.DIRECT) {
            output.write(data, 0, length); output.flush(); return
        }

        val rtt = currentRttMs.value
        val adaptiveDelay = when {
            rtt < 40 -> rnd.nextLong(1, 2)
            rtt < 120 -> rnd.nextLong(2, 4)
            else -> rnd.nextLong(5, 12)
        }
        val effectiveDelay = if (config.delay1 > 0) config.delay1 else adaptiveDelay

        if (length <= 5) {
            output.write(data, 0, length); output.flush(); return
        }

        try { socket.tcpNoDelay = true } catch (e: Throwable) {}

        var finalData = data
        var finalLen = length
        
        if (isProbableHttp(data, length)) {
            if (strategy == BypassStrategy.HTTP_METHOD_CASE_MANGLE || (strategy.family == StrategyFamily.HTTP && rnd.nextInt(100) < 20)) {
                finalData = FakePacketHelper.mangleHttpMethodCase(finalData, finalLen)
                finalLen = finalData.size
            }
            if (strategy == BypassStrategy.HTTP_HEADER_CASE_CHAOS) {
                finalData = FakePacketHelper.randomizeHeaderCase(finalData, finalLen)
                finalLen = finalData.size
            }
        }

        when (strategy.family) {
            StrategyFamily.HTTP -> StrategyHandlers.handleHttpStrategies(socket, output, finalData, finalLen, rnd, host, strategy)
            StrategyFamily.TLS -> StrategyHandlers.handleTlsStrategies(socket, output, finalData, finalLen, rnd, host, strategy)
            StrategyFamily.TCP -> StrategyHandlers.handleTcpStrategies(socket, output, finalData, finalLen, rnd, host, strategy)
            StrategyFamily.FRAGMENTATION -> StrategyHandlers.handleFragmentationStrategies(socket, output, finalData, finalLen, rnd, host, strategy, effectiveDelay)
            StrategyFamily.ADAPTIVE -> StrategyHandlers.handleAdaptiveStrategies(socket, output, finalData, finalLen, rnd, host, strategy, config)
            else -> {
                if (strategy == BypassStrategy.CHAOS) {
                    val picked = listOf(BypassStrategy.SNI_SPLIT, BypassStrategy.TCP_WINDOW_SHRINK, BypassStrategy.FRAGMENT_MULTI).random()
                    applyBypass(socket, output, data, length, config.copy(strategy = picked), host)
                } else {
                    output.write(finalData, 0, finalLen); output.flush()
                }
            }
        }
    }

    fun recordStrategyResult(host: String, strategy: BypassStrategy, success: Boolean, avgDuration: Long = 50L) {
        if (success) {
            recordSuccess(strategy, avgDuration, host)
        } else {
            recordFailure(strategy, host)
        }
    }

    suspend fun applyUdpBypass(socket: DatagramSocket, packet: DatagramPacket, config: SessionConfig, host: String) {
        val rnd = ThreadLocalRandom.current()
        val strategy = config.strategy
        if (strategy == BypassStrategy.DIRECT) {
            socket.send(packet); return
        }
        StrategyHandlers.handleUdpStrategies(socket, packet, rnd, host, strategy, config)
    }

    fun startLearningTask(scope: CoroutineScope) {
        scope.launch {
            while (isActive) {
                delay(TimeUnit.MINUTES.toMillis(15))
                DpiEngine.analyzeAndAdjust()
                DnsOptimizer.forceRefresh()
            }
        }
    }

    fun startNetworkWeatherSensor(scope: CoroutineScope) {
        scope.launch {
            val canaryHosts = listOf("1.1.1.1", "8.8.8.8", "9.9.9.9")
            while (isActive) {
                try {
                    val host = canaryHosts.random()
                    val start = System.currentTimeMillis()
                    withTimeout(2000) {
                        val s = Socket()
                        s.connect(InetSocketAddress(host, 53), 2000)
                        s.close()
                    }
                    val rtt = System.currentTimeMillis() - start
                    _currentRttMs.update { (it * 0.7 + rtt * 0.3).toLong().coerceIn(10, 2000) }
                } catch (e: Throwable) {
                    _currentRttMs.update { (it * 1.2).toLong().coerceAtMost(2000) }
                }
                delay(TimeUnit.MINUTES.toMillis(2))
            }
        }
    }

    private fun isProbableHttp(data: ByteArray, length: Int): Boolean {
        if (length < 8) return false
        val s = String(data, 0, minOf(length, 16), Charsets.US_ASCII)
        return s.startsWith("GET ") || s.startsWith("POST ") || s.startsWith("HEAD ") || s.startsWith("HTTP/")
    }

    private fun findHeaderEnd(data: ByteArray, length: Int): Int {
        for (i in 0..length - 4) {
            if (data[i] == '\r'.code.toByte() && data[i+1] == '\n'.code.toByte() &&
                data[i+2] == '\r'.code.toByte() && data[i+3] == '\n'.code.toByte()) return i + 4
        }
        return -1
    }
}
