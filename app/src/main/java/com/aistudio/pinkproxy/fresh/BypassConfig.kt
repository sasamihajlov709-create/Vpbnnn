package com.aistudio.pinkproxy.fresh

import android.content.Context
import android.net.VpnService
import android.util.Log
import androidx.core.content.edit
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.net.*
import java.util.*
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.io.*

object BypassConfig {
    private val _strategy = kotlinx.coroutines.flow.MutableStateFlow(BypassStrategy.SNI_SPLIT)
    private val _strat = MutableStateFlow(BypassStrategy.SNI_SPLIT)
    val strategy: StateFlow<BypassStrategy> = _strategy.asStateFlow()
    
    /**
     * Public API for UI / settings changes: delegates to RuntimeCoordinator for safe validation and single-point mutation.
     */
    fun setStrategy(new: BypassStrategy, transport: TransportType = TransportType.TCP, reason: String = "User Selection") {
        RuntimeCoordinator.transitionGlobalStrategy(new, transport, reason)
    }

    /**
     * Direct strategy assignment helper.
     */
    fun setGlobalStrategy(new: BypassStrategy) {
        _strategy.value = new
    }

    /**
     * Internal mutation called solely by RuntimeCoordinator after validation.
     */
    internal fun applyInternalStrategy(new: BypassStrategy) {
        _strategy.value = new
    }
    
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
    
    private val _currentNetworkType = MutableStateFlow(NetworkType.UNKNOWN)
    val currentNetworkType: StateFlow<NetworkType> = _currentNetworkType.asStateFlow()

    val _currentRttMs = MutableStateFlow(50L)
    val currentRttMs: StateFlow<Long> = _currentRttMs.asStateFlow()

    private val _isPanicModeFlow = MutableStateFlow(false)
    val isPanicModeFlow: StateFlow<Boolean> = _isPanicModeFlow.asStateFlow()

    private val _isKillSwitchEnabled = MutableStateFlow(false)
    val isKillSwitchEnabled: StateFlow<Boolean> = _isKillSwitchEnabled.asStateFlow()
    var forcedBenchmarkStrategy: BypassStrategy? = null
    fun setKillSwitch(enabled: Boolean, context: Context) {
        _isKillSwitchEnabled.value = enabled
        context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE).edit {
            putBoolean("kill_switch_enabled", enabled)
        }
    }

    private val _currentMtu = MutableStateFlow(1400)
    val currentMtu: StateFlow<Int> = _currentMtu.asStateFlow()

    private val _dnsType = MutableStateFlow(DnsType.AUTO)
    val dnsTypeFlow: StateFlow<DnsType> = _dnsType.asStateFlow()
    var dnsType: DnsType
        get() = _dnsType.value
        set(value) { _dnsType.value = value }

    private val _customDnsUrl = MutableStateFlow("https://dns.google/dns-query")
    val customDnsUrlFlow: StateFlow<String> = _customDnsUrl.asStateFlow()
    var customDnsUrl: String
        get() = _customDnsUrl.value
        set(value) { _customDnsUrl.value = value }

    @Volatile var isAutoTuning = true
    @Volatile var isDiagnosticMode = false
    @Volatile var frag1 = 1
    @Volatile var frag2 = 0
    @Volatile var frag3 = 0
    @Volatile var delay1 = 20L
    @Volatile var delay2 = 0L
    @Volatile var fakeTtl = 0
    @Volatile var blockQuic = false
    private val _quicBypassMode = MutableStateFlow(QuicBypassMode.AUTO)
    val quicBypassMode: StateFlow<QuicBypassMode> = _quicBypassMode.asStateFlow()
    
    fun setQuicBypassMode(mode: QuicBypassMode) {
        _quicBypassMode.value = mode
        blockQuic = (mode == QuicBypassMode.FORCE_BLOCK)
    }
    @Volatile var filterEch = true
    @Volatile var preferIpv6 = false
    @Volatile var includeIpv6 = true
    @Volatile var isCharging = true
    @Volatile var isPowerSaveMode = false
    @Volatile var isScreenOn = true
    @Volatile var batteryLevel = 100
    @Volatile var thermalStatus = 0
    @Volatile var activeVpnService: VpnService? = null

    private val _currentFragSizeState = MutableStateFlow(1)
    val currentFragSizeState: StateFlow<Int> = _currentFragSizeState.asStateFlow()

    fun updateTestingStrategies(list: List<BypassStrategy>) {
        _testingStrategies.value = list
    }

    private val SESSION_TTL = 30 * 60 * 1000L 
    private val censorHeuristic = ConcurrentHashMap<String, Int>()
    private val hostLockTime = ConcurrentHashMap<String, Long>()

    fun startDeviceMonitoring(context: Context) = DeviceMonitor.startDeviceMonitoring(context)

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
    fun setPanicMode(enabled: Boolean) { _isPanicModeFlow.value = enabled }

    fun updateMtu(context: Context, mtu: Int) {
        setMtu(mtu)
        val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
        prefs.edit { putInt("mtu_size", mtu) }
    }

    fun setMtu(mtu: Int) {
        val new = mtu.coerceIn(576, 1500)
        if (_currentMtu.value != new) {
            _currentMtu.value = new
            Log.i("BypassConfig", "MTU changed to $new")
        }
    }

    fun getNetworkType(): NetworkType = _currentNetworkType.value

    val censorshipLevel: Int get() = ProxyStats.censorshipIntensity.value
    var isStrictBypassMode: Boolean = false

    fun isHostCensored(host: String): Boolean = isHostProbablyCensored(host)
    fun isHostDirect(host: String): Boolean = HostClassifier.classify(host) == com.aistudio.pinkproxy.fresh.HostCategory.DIRECT

    private var warmupJob: Job? = null

    fun startWarmupTask(scope: CoroutineScope) {
        warmupJob?.cancel()
        warmupJob = scope.launch {
            while (isActive) {
                try {
                    val target = if (ThreadLocalRandom.current().nextBoolean()) "google.com" else "cloudflare.com"
                    DpiEngine.triggerMicroProbe(target, HostCategory.OTHER)
                } catch (e: kotlinx.coroutines.CancellationException) {
                    throw e
                } catch (e: Throwable) {}
                delay(TimeUnit.MINUTES.toMillis(15))
            }
        }
    }

    fun stopWarmupTask() {
        warmupJob?.cancel()
        warmupJob = null
    }

    fun setTtl(ttl: Int) { fakeTtl = ttl.coerceIn(0, 30) }
    val currentTtl: Int get() = if (fakeTtl > 0) fakeTtl else 3

    fun getFakeTtlForHost(host: String): Int {
        return if (fakeTtl > 0) fakeTtl else 3
    }

    fun panicOptimize() {
        _isPanicModeFlow.value = true
        setMtu(1200)
        frag1 = 1
        delay1 = 100L
    }

    fun updateNetworkType(type: NetworkType) {
        if (_currentNetworkType.value != type) {
            _currentNetworkType.value = type
            ProxyStats.resetScores()
            // DpiEngine.clearCircuitBreakers
        }
    }

    fun loadTuningSettings(context: Context) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
        isAutoTuning = prefs.getBoolean("is_auto_tuning", true)
        blockQuic = prefs.getBoolean("block_quic", false)
        filterEch = prefs.getBoolean("filter_ech", true)
        frag1 = prefs.getInt("frag1", 1)
        delay1 = prefs.getLong("delay1", 20L)
        fakeTtl = prefs.getInt("fakeTtl", 0)
        val savedStrat = prefs.getString("global_strategy", BypassStrategy.SNI_SPLIT.name)
        _strategy.value = try { BypassStrategy.valueOf(savedStrat ?: BypassStrategy.SNI_SPLIT.name) } catch (e: Exception) { BypassStrategy.SNI_SPLIT }
        
        val savedDns = prefs.getString("dns_strategy_type", DnsType.AUTO.name)
        dnsType = try { DnsType.valueOf(savedDns ?: DnsType.AUTO.name) } catch(e: Exception) { DnsType.AUTO }
        customDnsUrl = prefs.getString("custom_dns_url", "https://dns.google/dns-query") ?: "https://dns.google/dns-query"
        _isKillSwitchEnabled.value = prefs.getBoolean("kill_switch_enabled", false)
    }

    fun saveDnsSettings(context: Context, type: DnsType, customUrl: String? = null) {
        dnsType = type
        if (customUrl != null) customDnsUrl = customUrl
        context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE).edit {
            putString("dns_strategy_type", type.name)
            putString("custom_dns_url", customDnsUrl)
        }
    }

    fun saveBypassSettings(context: Context) = saveTuningSettings(context)

    fun saveTuningSettings(context: Context) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
        prefs.edit {
            putBoolean("is_auto_tuning", isAutoTuning)
            putBoolean("block_quic", blockQuic)
            putBoolean("filter_ech", filterEch)
            putInt("frag1", frag1)
            putLong("delay1", delay1)
            putInt("fakeTtl", fakeTtl)
            putString("global_strategy", _strategy.value.name)
        }
    }

    fun getBestStrategyForHost(host: String, transport: TransportType = TransportType.TCP): BypassStrategy {
        val now = System.currentTimeMillis()
        forcedBenchmarkStrategy?.let {
            if (DpiStrategySelector.isFamilyCompatible(it.family, transport) &&
                StrategyExecutionRegistry.isExecutorSupported(it, transport)) {
                return it
            }
        }
        if (!isAutoTuning) {
            val base = _strategy.value
            if (DpiStrategySelector.isFamilyCompatible(base.family, transport) &&
                StrategyExecutionRegistry.isExecutorSupported(base, transport) &&
                (DpiEngine.circuitBreakers[base] ?: 0L) < now) {
                return if (isStrictBypassMode && base == BypassStrategy.DIRECT) {
                    DpiStrategySelector.getDefaultFallback(transport)
                } else {
                    base
                }
            } else {
                return DpiStrategySelector.getDefaultFallback(transport)
            }
        }
        
        var best = DpiStrategySelector.getBestStrategy(HostClassifier.classify(host), host, transport)
        if (isStrictBypassMode && best == BypassStrategy.DIRECT) {
            best = DpiStrategySelector.getDefaultFallback(transport)
        }
        
        VpnRuntimeState.updateStrategy(best.name, DpiStrategySelector.getSelectionReasoning(best, host))
        
        return best
    }

    fun rotateGlobalStrategy(transport: TransportType = TransportType.TCP) {
        RuntimeCoordinator.requestGlobalStrategyRotation(transport, "BypassConfig Global Rotation")
    }

    fun recordSuccess(
        strategy: BypassStrategy,
        rtt: Long,
        host: String?,
        quality: ObservationQuality = ObservationQuality.APPLICATION_DATA_EXCHANGED,
        requestedStrategy: BypassStrategy? = null,
        effectiveStrategy: BypassStrategy? = null,
        transport: TransportType = TransportType.TCP
    ) {
        ProxyStats.recordGlobalSuccess(rtt)
        ProxyStats.reportStrategyResult(strategy, true)
        val cat = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
        DpiStrategySelector.recordResult(
            strategy = strategy,
            success = true,
            transport = transport,
            quality = quality,
            category = cat,
            latencyMs = rtt,
            host = host,
            requestedStrategy = requestedStrategy,
            effectiveStrategy = effectiveStrategy
        )
        if (rtt > 0) {
            TrafficShaper.updateRtt(rtt)
            _currentRttMs.value = (_currentRttMs.value * 7 + rtt) / 8
        }
        if (host != null) {
            censorHeuristic.remove(host)
            hostLockTime.remove(host)
        }
    }

    fun recordFailure(
        strategy: BypassStrategy,
        host: String?,
        reason: FailureReason = FailureReason.UNKNOWN,
        quality: ObservationQuality = ObservationQuality.CONNECT_ONLY,
        requestedStrategy: BypassStrategy? = null,
        effectiveStrategy: BypassStrategy? = null,
        transport: TransportType = TransportType.TCP
    ) {
        ProxyStats.recordCensorshipEvent(true)
        ProxyStats.reportStrategyResult(strategy, false)
        val cat = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
        DpiStrategySelector.recordResult(
            strategy = strategy,
            success = false,
            transport = transport,
            quality = quality,
            category = cat,
            reason = reason,
            host = host,
            requestedStrategy = requestedStrategy,
            effectiveStrategy = effectiveStrategy
        )
        if (host != null) {
            val count = censorHeuristic.getOrDefault(host, 0) + 1
            censorHeuristic[host] = count
            if (count >= 5) hostLockTime[host] = System.currentTimeMillis()
        }
    }

    fun getSessionConfig(host: String, strategy: BypassStrategy, rtt: Long, transport: TransportType = TransportType.TCP): SessionConfig {
        val rnd = ThreadLocalRandom.current()
        val intensity = ProxyStats.censorshipIntensity.value
        var effectiveStrategy = if (isPanicMode && rnd.nextInt(100) < 80) BypassStrategy.BYEBYEDPI_HYBRID else strategy
        
        if (!DpiStrategySelector.isFamilyCompatible(effectiveStrategy.family, transport) ||
            !StrategyExecutionRegistry.isExecutorSupported(effectiveStrategy, transport)) {
            effectiveStrategy = DpiStrategySelector.getDefaultFallback(transport)
        }

        if (isStrictBypassMode && effectiveStrategy == BypassStrategy.DIRECT) {
            effectiveStrategy = DpiStrategySelector.getDefaultFallback(transport)
        }
        val f1 = if (frag1 > 0) frag1 else DpiEngine.getRecommendedFragSize()
        val f2 = if (frag2 > 0) frag2 else (f1 + rnd.nextInt(1, 4))
        val f3 = if (frag3 > 0) frag3 else (f2 + rnd.nextInt(1, 4))
        val baseDelay = DpiEngine.getRecommendedDelay()
        val d1 = if (rtt > 0) Math.max(baseDelay, Math.min(rtt / 4, 150L)) else baseDelay
        val ttl = if (fakeTtl == 0) rnd.nextInt(3, 8) else fakeTtl
        return SessionConfig(
            strategy = effectiveStrategy,
            requestedStrategy = strategy,
            frag1 = f1,
            frag2 = f2,
            frag3 = f3,
            delay1 = d1,
            fakeTtl = ttl,
            useIPv6 = host.contains(":"),
            mss = if (intensity > 75) rnd.nextInt(512, 1000) else 1440
        )
    }

    fun setGlobalStrategy(strategy: BypassStrategy, transport: TransportType = TransportType.TCP, reason: String = "Recovery State Machine") {
        setStrategy(strategy, transport, reason)
    }
    fun getStrategyMetrics(): List<StrategyMetric> = DpiStrategySelector.getStrategyMetrics()

    val strategyMetrics: kotlinx.coroutines.flow.Flow<List<StrategyMetric>> = flow {
        while (true) {
            emit(getStrategyMetrics())
            kotlinx.coroutines.delay(5000)
        }
    }.shareIn(
        scope = CoroutineScope(Dispatchers.Default + SupervisorJob()),
        started = SharingStarted.WhileSubscribed(5000),
        replay = 1
    )

    fun resetScores() {
        ProxyStats.resetScores()
        // DpiEngine.resetStrategyScoresForNetworkChange()
    }

    fun clearScores(context: Context) {
        resetScores()
    }

    fun getFallbackStrategy(
        current: BypassStrategy,
        transport: TransportType = TransportType.TCP,
        reason: FailureReason? = null,
        host: String? = null,
        category: HostCategory? = null
    ): BypassStrategy {
        return DpiStrategySelector.getFallbackStrategy(strategy = current, transport = transport) ?: when (transport) {
            TransportType.TCP -> when (current.family) {
                StrategyFamily.TLS -> BypassStrategy.TLS_SNI_GREASE
                StrategyFamily.HTTP -> BypassStrategy.HTTP_METHOD_CASE_MANGLE
                StrategyFamily.TCP -> BypassStrategy.TCP_WINDOW_SHRINK
                StrategyFamily.FRAGMENTATION -> BypassStrategy.FRAGMENT_MULTI
                else -> BypassStrategy.SNI_SPLIT
            }
            TransportType.UDP -> BypassStrategy.UDP_COMBINED_HYBRID
            TransportType.DNS -> BypassStrategy.DNS_OVER_TCP
        }
    }
    suspend fun applyBypass(socket: Socket, output: OutputStream, data: ByteArray, length: Int, config: SessionConfig, host: String) = 
        BypassApplier.applyBypass(socket, output, data, length, config, host)
    suspend fun applyUdpBypass(socket: DatagramSocket, packet: DatagramPacket, config: SessionConfig, host: String) = 
        BypassApplier.applyUdpBypass(socket, packet, config, host)
}
