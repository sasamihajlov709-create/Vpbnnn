package com.aistudio.pinkproxy.fresh

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.service.quicksettings.TileService
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

class PinkVpnService : VpnService() {

    companion object {
        @JvmStatic var instance: PinkVpnService? = null
        private val _isRunning = MutableStateFlow(false)
        @JvmStatic val isRunning: StateFlow<Boolean> = _isRunning.asStateFlow()

        @JvmStatic var isExcludeMode = true
        @JvmStatic val selectedPackages = java.util.Collections.newSetFromMap(java.util.concurrent.ConcurrentHashMap<String, Boolean>())

        private const val PROXY_PORT = 18080
        private val proxySecret = java.util.UUID.randomUUID().toString()

        @JvmStatic fun loadFilterSettings(context: Context) {
            val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
            isExcludeMode = prefs.getBoolean("filter_exclude_mode", true)
            val saved = prefs.getString("filter_packages", "") ?: ""
            selectedPackages.clear()
            if (saved.isNotEmpty()) {
                selectedPackages.addAll(saved.split(","))
            }
        }

        @JvmStatic fun saveFilterSettings(context: Context) {
            val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
            prefs.edit().apply {
                putBoolean("filter_exclude_mode", isExcludeMode)
                putString("filter_packages", selectedPackages.joinToString(","))
                apply()
            }
        }

        @JvmStatic fun saveVpnState(context: Context, active: Boolean) {
            context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
                .edit().putBoolean("vpn_was_active", active).apply()
        }

        @JvmStatic fun updateTile(context: Context) {
            try {
                TileService.requestListeningState(context, ComponentName(context, PinkProxyTileService::class.java))
            } catch (e: Exception) {
                Log.w("PinkVpnService", "Failed to request tile listening state: ${e.message}")
            }
        }
    }

    val engineScope = CoroutineScope(ProxyDispatcher.io + SupervisorJob() + ProxyDispatcher.globalHandler)
    private var sessionScope: CoroutineScope? = null

    fun getServiceScope(): CoroutineScope = engineScope

    private lateinit var notificationController: VpnNotificationController
    private lateinit var recoveryCoordinator: VpnRecoveryCoordinator
    private var healthMonitor: VpnHealthMonitor? = null
    private var vpnTunnelManager: VpnTunnelManager? = null
    private var vpnNetworkMonitor: VpnNetworkMonitor? = null
    private var proxyServer: PinkProxyServer? = null

    private var wakeLock: android.os.PowerManager.WakeLock? = null
    private var wifiLock: android.net.wifi.WifiManager.WifiLock? = null

    private val serviceLock = Mutex()
    @Volatile private var isStopping = false

    override fun onCreate() {
        super.onCreate()
        instance = this
        BypassConfig.activeVpnService = this
        ProxyDispatcher.context = this

        notificationController = VpnNotificationController(this)
        recoveryCoordinator = VpnRecoveryCoordinator(this)
        vpnTunnelManager = VpnTunnelManager(this)

        val pm = getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
        wakeLock = pm.newWakeLock(android.os.PowerManager.PARTIAL_WAKE_LOCK, "PinkProxy:VpnWakeLock")

        val wm = getSystemService(Context.WIFI_SERVICE) as android.net.wifi.WifiManager
        wifiLock = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            wm.createWifiLock(android.net.wifi.WifiManager.WIFI_MODE_FULL_LOW_LATENCY, "PinkProxy:WifiLock")
        } else {
            @Suppress("DEPRECATION")
            wm.createWifiLock(android.net.wifi.WifiManager.WIFI_MODE_FULL_HIGH_PERF, "PinkProxy:WifiLock")
        }

        BypassConfig.startDeviceMonitoring(this)
        PrefetchManager.start(this, this)
        DnsCacheManager.load(this)
        BypassConfig.loadTuningSettings(this)
        loadFilterSettings(this)

        healthMonitor = VpnHealthMonitor(
            context = this,
            proxyPort = PROXY_PORT,
            getProxyServer = { proxyServer },
            restartProxyServer = { restartProxyServer() },
            restartVpnSession = { recoveryCoordinator.triggerRestart() },
            isVpnRunning = { _isRunning.value },
            protectSocket = { socket -> protect(socket) }
        )

        registerNetworkMonitor()

        engineScope.launch {
            var lastMtu = BypassConfig.currentMtu.value
            BypassConfig.currentMtu.collect { newMtu ->
                if (_isRunning.value && vpnTunnelManager?.isEstablished() == true) {
                    val diff = Math.abs(newMtu - lastMtu)
                    if (diff >= 32) {
                        ProxyStats.logRecovery("Network Optimization: MTU changed to $newMtu. Re-establishing tunnel.")
                        lastMtu = newMtu
                        recoveryCoordinator.triggerRestart()
                    }
                }
            }
        }
    }

    private fun registerNetworkMonitor() {
        vpnNetworkMonitor = VpnNetworkMonitor(
            context = this,
            networkChangeCallback = { network, type ->
                try {
                    setUnderlyingNetworks(network?.let { arrayOf(it) })
                } catch (e: Exception) {
                    Log.e("PinkVpnService", "Failed to set underlying networks: ${e.message}")
                }

                if (network != null) {
                    ProxyStats.logRecovery("Switching to $type network. Re-calibrating DPI engine.")
                    DpiEngine.resetStrategyScoresForNetworkChange()
                    ProxyStats.resetMssFailureCount()
                    DnsCacheManager.onNetworkChanged()
                    RobustResolver.clearCache()

                    if (_isRunning.value) {
                        engineScope.launch {
                            delay(1500)
                            if (_isRunning.value) {
                                ProxyStats.logRecovery("Network transition detected. Refreshing VPN tunnel.")
                                recoveryCoordinator.triggerRestart()
                            }
                        }
                    }
                }
            },
            capabilitiesChangeCallback = { _, capabilities ->
                val isWifi = capabilities.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI)
                val isMobile = capabilities.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR)

                if (isWifi && _isRunning.value) {
                    try {
                        if (wifiLock?.isHeld == false) wifiLock?.acquire()
                    } catch (e: Exception) {
                        Log.v("PinkVpnService", "WifiLock acquire error: ${e.message}")
                    }
                } else {
                    try {
                        if (wifiLock?.isHeld == true) wifiLock?.release()
                    } catch (e: Exception) {
                        Log.v("PinkVpnService", "WifiLock release error: ${e.message}")
                    }
                }

                BypassConfig.updateNetworkType(if (isWifi) NetworkType.WIFI else if (isMobile) NetworkType.MOBILE else NetworkType.NONE)
            }
        )
        vpnNetworkMonitor?.start()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        notificationController.showNotification()
        val action = intent?.action
        if (action == "STOP") {
            saveVpnState(this, false)
            engineScope.launch {
                serviceLock.withLock {
                    try {
                        stopVpnInternal()
                        _isRunning.value = false
                        VpnRuntimeState.updateState(VpnLifecycleState.STOPPING)
                        stopSelf()
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        Log.e("PinkVpnService", "Stop service error: ${e.message}", e)
                    }
                }
            }
            return START_NOT_STICKY
        }

        if (action == "CHANGE_STRATEGY") {
            engineScope.launch {
                try {
                    ProxyStats.logRecovery("Strategy Changed: Applied dynamically & instantly")
                    notificationController.showNotification()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.e("PinkVpnService", "Change strategy error: ${e.message}", e)
                }
            }
            return START_STICKY
        }

        if (action == "RESTART") {
            engineScope.launch {
                serviceLock.withLock {
                    try {
                        ProxyStats.logRecovery("Core System Re-Started")
                        stopVpnInternal()
                        delay(500)
                        notificationController.showNotification()
                        startVpnInternal()
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        Log.e("PinkVpnService", "Restart internal error: ${e.message}", e)
                    }
                }
            }
            return START_STICKY
        }

        saveVpnState(this, true)
        VpnRuntimeState.updateState(VpnLifecycleState.STARTING)
        engineScope.launch {
            serviceLock.withLock {
                try {
                    startVpnInternal()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.e("PinkVpnService", "Start action error: ${e.message}", e)
                    VpnRuntimeState.updateState(VpnLifecycleState.FAILED, "Start failed: ${e.message}")
                }
            }
        }
        updateTile(this)
        return START_STICKY
    }

    private fun startVpn() {
        engineScope.launch {
            serviceLock.withLock {
                try {
                    startVpnInternal()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.e("PinkVpnService", "Start internal error: ${e.message}", e)
                }
            }
        }
    }

    private suspend fun startVpnInternal() = withContext(ProxyDispatcher.io) {
        if (_isRunning.value) return@withContext
        isStopping = false
        Log.i("PinkVpnService", "Starting VPN internal sequence...")

        try {
            ProxyStats.reset(false)
            ServiceChecker.proxyPort = PROXY_PORT

            // 1. Initialize DNS
            RobustResolver.initialize(engineScope)
            RobustResolver.startDnsOptimizer(engineScope, this@PinkVpnService)

            // 2. Start Proxy Server
            proxyServer?.stop()
            proxyServer = null
            delay(150)
            proxyServer = PinkProxyServer(this@PinkVpnService, PROXY_PORT, proxySecret)
            proxyServer?.start()

            // 3. Start DPI Engine & Censorship Expert
            DpiEngine.start(this@PinkVpnService)
            CensorshipExpert.start()

            sessionScope?.cancel()
            sessionScope = CoroutineScope(ProxyDispatcher.io + SupervisorJob())

            val systemDnsIps = try {
                val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
                val activeNet = cm.activeNetwork
                val linkProps = cm.getLinkProperties(activeNet)
                linkProps?.dnsServers?.mapNotNull { it.hostAddress }?.filter { it.contains(".") } ?: emptyList()
            } catch (e: Exception) {
                emptyList()
            }

            val dnsServers = when (BypassConfig.dnsType) {
                DnsType.SYSTEM -> if (systemDnsIps.isNotEmpty()) systemDnsIps else listOf("1.1.1.1", "8.8.8.8")
                DnsType.GOOGLE_DOH -> listOf("8.8.8.8", "8.8.4.4")
                DnsType.CLOUDFLARE_DOH -> listOf("1.1.1.1", "1.0.0.1")
                DnsType.ADGUARD_DOH -> listOf("94.140.14.14", "94.140.15.15")
                DnsType.QUAD9_DOH -> listOf("9.9.9.9", "149.112.112.112")
                DnsType.CUSTOM_UDP, DnsType.CUSTOM_TCP, DnsType.CUSTOM_DOH -> {
                    val ips = extractIpsFromDnsUrl(BypassConfig.customDnsUrl)
                    if (ips.isNotEmpty()) ips else listOf("1.1.1.1", "8.8.8.8")
                }
                else -> if (systemDnsIps.isNotEmpty()) systemDnsIps else listOf("1.1.1.1", "8.8.8.8")
            }

            // 4. Establish TUN interface
            val pfd = try {
                vpnTunnelManager?.establish(
                    sessionName = "PinkProxy VPN",
                    mtu = BypassConfig.currentMtu.value,
                    addressV4 = "10.0.0.2",
                    prefixV4 = 24,
                    dnsServers = dnsServers,
                    includeIpv6 = BypassConfig.includeIpv6,
                    isExcludeMode = isExcludeMode,
                    selectedPackages = selectedPackages,
                    appPackageName = packageName,
                    allowBypass = !BypassConfig.isKillSwitchEnabled.value,
                    isBlocking = BypassConfig.isKillSwitchEnabled.value
                ) ?: throw java.io.IOException("Failed to establish tunnel")
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                Log.w("PinkVpnService", "Emergency fallback TUN activated! Reason: ${e.message}. Reconfiguring: IPv4-only, MTU 1400, Default DNS 8.8.8.8")
                VpnRuntimeState.updateState(VpnLifecycleState.STARTING, "Fallback tunnel mode activated (IPv4-only)")
                vpnTunnelManager?.establish(
                    sessionName = "PinkProxy VPN",
                    mtu = 1400,
                    addressV4 = "10.0.0.2",
                    prefixV4 = 24,
                    dnsServers = listOf("8.8.8.8"),
                    includeIpv6 = false,
                    isExcludeMode = true,
                    selectedPackages = emptySet(),
                    appPackageName = packageName,
                    allowBypass = !BypassConfig.isKillSwitchEnabled.value,
                    isBlocking = BypassConfig.isKillSwitchEnabled.value
                ) ?: throw e
            }

            AutoTtlProber.startProbing(engineScope, this@PinkVpnService)

            try {
                wakeLock?.acquire(24 * 60 * 60 * 1000L)
            } catch (e: Exception) {
                Log.e("PinkVpnService", "Failed to acquire wakeLock: ${e.message}")
            }

            _isRunning.value = true

            // 5. Start tun2socks engine
            startTun2Socks(pfd, PROXY_PORT)

            // 6. Now that proxy & tun2socks are fully running, start health checkers & monitors
            ServiceChecker.startChecking(engineScope, this@PinkVpnService)
            RecoveryManager.startHealthCheck(engineScope)
            healthMonitor?.start(engineScope)

            startSessionWarmup()

            VpnRuntimeState.updateState(VpnLifecycleState.RUNNING)
            VpnRuntimeState.clearError()
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            Log.e("PinkVpnService", "Error starting VPN", e)
            VpnRuntimeState.updateState(VpnLifecycleState.FAILED, "Critical startup error: ${e.localizedMessage}")
            stopVpn()
        }
    }

    private fun startSessionWarmup() {
        BypassConfig.startWarmupTask(engineScope)
        engineScope.launch {
            delay(5000)
            ServiceChecker.runActiveProbing(this@PinkVpnService)
        }
    }

    private fun extractIpsFromDnsUrl(url: String): List<String> {
        val ipRegex = Regex("""\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b""")
        return ipRegex.findAll(url).map { it.value }.toList()
    }

    private fun startTun2Socks(vpnInterface: ParcelFileDescriptor, proxyPort: Int) {
        try {
            engine.Engine.touch()
            val key = engine.Key()
            key.setProxy("socks5://$proxySecret:$proxySecret@127.0.0.1:$proxyPort")
            val dupFd = vpnInterface.dup()
            val fd = dupFd.detachFd()
            key.setDevice("fd://$fd")
            key.setLogLevel("info")
            engine.Engine.insert(key)
            engineScope.launch {
                try {
                    engine.Engine.start()
                    Log.i("PinkVpnService", "tun2socks stopped naturally")
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.e("PinkVpnService", "tun2socks run-time error", e)
                    VpnRuntimeState.updateState(VpnLifecycleState.ERROR, "Transport engine error: ${e.localizedMessage}")
                }
            }
            Log.i("PinkVpnService", "tun2socks started on fd $fd")
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e("PinkVpnService", "Failed to start tun2socks", e)
            VpnRuntimeState.updateState(VpnLifecycleState.FAILED, "Transport engine init failed: ${e.localizedMessage}")
            throw e
        }
    }

    private fun stopTun2Socks() {
        try {
            engine.Engine.stop()
        } catch (e: Exception) {
            Log.e("PinkVpnService", "Failed to stop tun2socks: ${e.message}")
        }
    }

    private fun stopVpn() {
        engineScope.launch {
            serviceLock.withLock {
                try {
                    stopVpnInternal()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.e("PinkVpnService", "Stop internal error: ${e.message}", e)
                }
            }
        }
    }

    private suspend fun stopVpnInternal() = withContext(ProxyDispatcher.io) {
        if (isStopping) return@withContext
        isStopping = true
        Log.d("PinkVpnService", "Executing synchronized stop sequence...")

        try {
            _isRunning.value = false
            VpnRuntimeState.updateState(VpnLifecycleState.STOPPING)

            healthMonitor?.stop()

            sessionScope?.cancel()
            sessionScope = null

            DnsCacheManager.save(this@PinkVpnService)

            stopTun2Socks()
            proxyServer?.stop()
            proxyServer = null

            ServiceChecker.stopChecking()
            DpiEngine.stop()
            BypassConfig.stopWarmupTask()
            RobustResolver.stopBackgroundProber()
            CensorshipExpert.stop()
            PrefetchManager.stop()
            AutoTtlProber.stopProbing()
            DnsProtocols.clearPool()
            UdpTransportHandler.clearBuffers()
            RecoveryManager.stopHealthCheck()
            DeviceMonitor.stopDeviceMonitoring(this@PinkVpnService)

            vpnNetworkMonitor?.stop()
            vpnNetworkMonitor = null

            vpnTunnelManager?.close()

            try {
                if (wakeLock?.isHeld == true) wakeLock?.release()
                if (wifiLock?.isHeld == true) wifiLock?.release()
            } catch (e: Exception) {
                Log.v("PinkVpnService", "Lock release error: ${e.message}")
            }

            notificationController.stopNotification()
            updateTile(this@PinkVpnService)
            VpnRuntimeState.updateState(VpnLifecycleState.IDLE)
        } finally {
            isStopping = false
        }
    }

    @Suppress("DEPRECATION")
    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level >= android.content.ComponentCallbacks2.TRIM_MEMORY_MODERATE) {
            ProxyStats.releaseAllPools()
            DnsCacheManager.ensureEfficiency()
            RobustResolver.clearCache()
            java.lang.System.gc()
        }
    }

    override fun onRevoke() {
        super.onRevoke()
        stopVpn()
    }

    fun restartProxyServer() {
        engineScope.launch(ProxyDispatcher.io) {
            serviceLock.withLock {
                if (isStopping || !_isRunning.value) return@withLock
                try {
                    proxyServer?.stop()
                    proxyServer = null
                    delay(250)
                    proxyServer = PinkProxyServer(this@PinkVpnService, PROXY_PORT, proxySecret)
                    proxyServer?.start()
                    ProxyStats.logRecovery("Proxy server restarted successfully")
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.e("PinkVpnService", "Failed to restart proxy server: ${e.message}")
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        PrefetchManager.stop()
        DnsCacheManager.save(this)
        healthMonitor?.stop()

        runBlocking {
            try {
                withTimeout(2000) {
                    stopVpnInternal()
                }
            } catch (e: Exception) {
                Log.e("PinkVpnService", "Shutdown timed out or failed: ${e.message}", e)
            }
        }

        vpnNetworkMonitor?.stop()
        vpnNetworkMonitor = null

        engineScope.cancel()
        instance = null
        BypassConfig.activeVpnService = null
        ProxyDispatcher.context = null
    }
}
