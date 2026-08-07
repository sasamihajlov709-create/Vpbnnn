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
    private val _strategy = MutableStateFlow(BypassStrategy.SNI_SPLIT)
    val strategy: StateFlow<BypassStrategy> = _strategy.asStateFlow()
    
    fun setStrategy(new: BypassStrategy) {
        _strategy.value = new
        VpnRuntimeState.updateStrategy(new.name, DpiStrategySelector.getSelectionReasoning(new))
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
    @Volatile var preferIpv6 = false
    @Volatile var isCharging = true
    @Volatile var isPowerSaveMode = false
    @Volatile var batteryLevel = 100
    @Volatile var thermalStatus = 0
    @Volatile var activeVpnService: VpnService? = null

    private val _currentFragSizeState = MutableStateFlow(1)
    val currentFragSizeState: StateFlow<Int> = _currentFragSizeState.asStateFlow()

    fun updateTestingStrategies(list: List<BypassStrategy>) {
        _testingStrategies.value = list
    }

    private val hostStrategyMemory = ConcurrentHashMap<String, Pair<BypassStrategy, Long>>()

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

    fun startWarmupTask(scope: CoroutineScope) {
        scope.launch {
            while (isActive) {
                try {
                    val target = if (ThreadLocalRandom.current().nextBoolean()) "google.com" else "cloudflare.com"
                    DpiEngine.triggerMicroProbe(target, HostCategory.OTHER)
                } catch (e: Throwable) {}
                delay(TimeUnit.MINUTES.toMillis(15))
            }
        }
    }

    fun setTtl(ttl: Int) { fakeTtl = ttl }
    val currentTtl: Int get() = 64 // Standard TTL for real packets

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
            hostStrategyMemory.clear()
            ProxyStats.resetScores()
            DpiEngine.clearCircuitBreakers()
            DpiEngine.resetStrategyScoresForNetworkChange()
            AutoTtlProber.resetOnNetworkChange()
        }
    }

    fun loadTuningSettings(context: Context) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
        isAutoTuning = prefs.getBoolean("is_auto_tuning", true)
        blockQuic = prefs.getBoolean("block_quic", false)
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
            putInt("frag1", frag1)
            putLong("delay1", delay1)
            putInt("fakeTtl", fakeTtl)
            putString("global_strategy", _strategy.value.name)
        }
    }

    fun getBestStrategyForHost(host: String): BypassStrategy {
        forcedBenchmarkStrategy?.let { return it }
        if (!isAutoTuning) return _strategy.value
        val now = System.currentTimeMillis()
        hostStrategyMemory[host]?.let { (remembered, expiry) ->
            if (now < expiry) return remembered
        }
        val best = DpiEngine.getBestStrategy(HostClassifier.classify(host), host)
        hostStrategyMemory[host] = best to (now + SESSION_TTL)
        
        if (java.util.concurrent.ThreadLocalRandom.current().nextInt(100) < 5) {
            VpnRuntimeState.updateStrategy(best.name, DpiStrategySelector.getSelectionReasoning(best))
        }
        
        return best
    }

    fun rotateGlobalStrategy() {
        val best = BypassStrategy.entries.filter { it != BypassStrategy.DIRECT && it != _strategy.value }.random()
        _strategy.value = best
        VpnRuntimeState.updateStrategy(best.name)
        ProxyStats.logRecovery("Strategy rotated: ${best.name}")
    }

    fun recordSuccess(strat: BypassStrategy, rtt: Long, host: String?) {
        ProxyStats.recordGlobalSuccess(rtt)
        ProxyStats.reportStrategyResult(strat, true)
        val cat = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
        DpiEngine.recordResult(strat, true, cat, latencyMs = rtt, host = host)
        if (rtt > 0) {
            TrafficShaper.updateRtt(rtt)
            _currentRttMs.value = (_currentRttMs.value * 7 + rtt) / 8
        }
        if (host != null) {
            censorHeuristic.remove(host)
            hostLockTime.remove(host)
        }
    }

    fun recordFailure(strat: BypassStrategy, host: String?, reason: FailureReason = FailureReason.UNKNOWN) {
        ProxyStats.recordCensorshipEvent(true)
        ProxyStats.reportStrategyResult(strat, false)
        val cat = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
        DpiEngine.recordResult(strat, false, cat, reason, host = host)
        if (host != null) {
            val count = censorHeuristic.getOrDefault(host, 0) + 1
            censorHeuristic[host] = count
            if (count >= 5) hostLockTime[host] = System.currentTimeMillis()
        }
    }

    fun getSessionConfig(host: String, strategy: BypassStrategy, rtt: Long): SessionConfig {
        val rnd = ThreadLocalRandom.current()
        val intensity = ProxyStats.censorshipIntensity.value
        val effectiveStrategy = if (isPanicMode && rnd.nextInt(100) < 80) DpiEngine.getBestExtremeStrategy(host) else strategy
        val f1 = DpiEngine.getRecommendedFragSize()
        val d1 = DpiEngine.getRecommendedDelay()
        val ttl = if (fakeTtl == 0) rnd.nextInt(3, 8) else fakeTtl
        return SessionConfig(
            strategy = effectiveStrategy,
            frag1 = f1,
            delay1 = d1,
            fakeTtl = ttl,
            useIPv6 = host.contains(":") || (rnd.nextInt(100) < 15 && intensity > 60),
            mss = if (intensity > 75) rnd.nextInt(512, 1000) else 1440
        )
    }

    fun setGlobalStrategy(strat: BypassStrategy) { _strategy.value = strat }
    fun getStrategyMetrics(): List<StrategyMetric> = DpiStrategySelector.getStrategyMetrics()

    val strategyMetrics: kotlinx.coroutines.flow.Flow<List<StrategyMetric>> = flow {
        while (true) {
            emit(getStrategyMetrics())
            kotlinx.coroutines.delay(5000)
        }
    }

    fun resetScores() {
        ProxyStats.resetScores()
        DpiEngine.resetStrategyScoresForNetworkChange()
    }

    fun clearScores(context: Context) {
        resetScores()
    }

    fun getFallbackStrategy(current: BypassStrategy): BypassStrategy {
        return when (current.family) {
            StrategyFamily.TLS -> BypassStrategy.TLS_SNI_GREASE
            StrategyFamily.HTTP -> BypassStrategy.HTTP_METHOD_CASE_MANGLE
            StrategyFamily.TCP -> BypassStrategy.TCP_WINDOW_SHRINK
            StrategyFamily.FRAGMENTATION -> BypassStrategy.FRAGMENT_MULTI
            else -> BypassStrategy.DIRECT
        }
    }
    suspend fun applyBypass(socket: Socket, output: OutputStream, data: ByteArray, length: Int, config: SessionConfig, host: String) = 
        BypassApplier.applyBypass(socket, output, data, length, config, host)
    suspend fun applyUdpBypass(socket: DatagramSocket, packet: DatagramPacket, config: SessionConfig, host: String) = 
        BypassApplier.applyUdpBypass(socket, packet, config, host)
}
