package com.aistudio.pinkproxy.fresh
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine

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

        internal const val PROXY_PORT = 18080
        internal val proxySecret = java.util.UUID.randomUUID().toString()

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

    val serviceScope = CoroutineScope(ProxyDispatcher.io + SupervisorJob() + ProxyDispatcher.globalHandler)
    


    private lateinit var notificationController: VpnNotificationController
    private lateinit var recoveryCoordinator: VpnRecoveryCoordinator
    private var healthMonitor: VpnHealthMonitor? = null
    private var vpnTunnelManager: VpnTunnelManager? = null
    private var vpnNetworkMonitor: VpnNetworkMonitor? = null
    private var proxyServer: PinkProxyServer? = null
    private lateinit var vpnStartupCoordinator: VpnStartupCoordinator

    private var wakeLock: android.os.PowerManager.WakeLock? = null
    private var wifiLock: android.net.wifi.WifiManager.WifiLock? = null

    private val serviceLock = Mutex()
    @Volatile     private var notificationJob: Job? = null
    
    private fun startDynamicNotification() {
        notificationJob?.cancel()
        notificationJob = serviceScope.launch {
            kotlinx.coroutines.flow.combine(
                BypassConfig.tcpStrategy,
                ProxyStats.activeFlows,
                ProxyStats.censorshipIntensity
            ) { strat, flows, intensity ->
                val activeCount = flows.size
                val panic = if (intensity > 50) " | PANIC" else ""
                val subtext = "Str: ${strat?.name ?: "Pending"} | Active: $activeCount$panic"
                subtext
            }.collectLatest { subtext ->
                if (_isRunning.value) {
                    notificationController.showNotification("Engine Active", subtext, isUpdate = true)
                }
            }
        }
    }
    
    private fun stopDynamicNotification() {
        notificationJob?.cancel()
        notificationJob = null
    }
    private var isStopping = false
    private var activeNetworkProfile: NetworkProfile = NetworkProfile.UNKNOWN

    override fun onCreate() {
        super.onCreate()
        instance = this
        BypassConfig.activeVpnService = this
        ProxyDispatcher.context = this.applicationContext

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

        vpnStartupCoordinator = VpnStartupCoordinator(
            vpnService = this,
            vpnTunnelManager = vpnTunnelManager!!,
            transportEngineCoordinator = transportEngineCoordinator,
            recoveryCoordinator = recoveryCoordinator,
            healthMonitor = healthMonitor!!
        )

        registerNetworkMonitor()

        serviceScope.launch {
            var lastMtu = BypassConfig.getMtuForTransport(TransportType.TCP)
            BypassConfig.isPanicModeFlow.collect { _ ->
                val newMtu = BypassConfig.getMtuForTransport(TransportType.TCP)
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
                    val oldProfile = activeNetworkProfile
                    val profile = NetworkProfileManager.currentProfile.value
                    activeNetworkProfile = profile
                    ProxyStats.logRecovery("Network connected: ${profile.displayName} ($type). Restoring profile knowledge.")
                    DpiEngine.switchNetworkProfile(oldProfile, profile, this)
                    AutoTtlProber.switchNetworkProfile(profile)
                    ProxyStats.resetMssFailureCount()
                    DnsCacheManager.onNetworkChanged()
                    RobustResolver.clearCache()
                    ProactiveAutoTuner.startProactiveTune(this, this)

                    if (_isRunning.value) {
                        serviceScope.launch {
                            delay(1500)
                            if (_isRunning.value) {
                                ProxyStats.logRecovery("Network transition detected. Refreshing VPN tunnel.")
                                recoveryCoordinator.triggerRestart()
                            }
                        }
                    }
                }
            },
            capabilitiesChangeCallback = { net, capabilities ->
                val cm = getSystemService(android.content.Context.CONNECTIVITY_SERVICE) as? android.net.ConnectivityManager
                val activeNet = cm?.activeNetwork
                if (activeNet == null || activeNet == net) {
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
            }
        )
        vpnNetworkMonitor?.start()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        try { notificationController.showNotification() } catch(e: Exception) { Log.e("PinkVpnService", "startForeground failure", e); serviceScope.launch { stopVpnInternal() }; stopSelf() }
        val action = intent?.action
        if (action == "STOP") {
            saveVpnState(this, false)
            serviceScope.launch {
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
            serviceScope.launch {
                try {
                    ProxyStats.logRecovery("Strategy Changed: Applied dynamically & instantly")
                    try { notificationController.showNotification() } catch(e: Exception) { Log.e("PinkVpnService", "startForeground failure", e); serviceScope.launch { stopVpnInternal() }; stopSelf() }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.e("PinkVpnService", "Change strategy error: ${e.message}", e)
                }
            }
            return START_STICKY
        }

        if (action == "RESTART") {
            serviceScope.launch {
                serviceLock.withLock {
                    try {
                        ProxyStats.logRecovery("Core System Re-Started")
                        stopVpnInternal()
                        delay(500)
                        try { notificationController.showNotification() } catch(e: Exception) { Log.e("PinkVpnService", "startForeground failure", e); serviceScope.launch { stopVpnInternal() }; stopSelf() }
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
        serviceScope.launch {
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
        serviceScope.launch {
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
        startDynamicNotification()

        val session = VpnSessionManager.currentSession ?: return@withContext
        session.controlPlaneScope.launch {
            com.aistudio.pinkproxy.fresh.cronet.CronetEngineProvider.initialize(this@PinkVpnService)
        }

        val success = vpnStartupCoordinator.startVpn(
            proxyPort = PROXY_PORT,
            proxySecret = proxySecret,
            session = session,
            isExcludeMode = isExcludeMode,
            selectedPackages = selectedPackages,
            onProxyServerStarted = { newProxy -> proxyServer = newProxy }
        )

        if (success) {
            _isRunning.value = true
            startSessionWarmup()
        } else {
            _isRunning.value = false
            stopVpnInternal()
        }
    }

    private fun startSessionWarmup() {
        VpnSessionManager.currentSession?.controlPlaneScope?.launch {
            delay(5000)
            ServiceChecker.runActiveProbing(this@PinkVpnService)
        }
    }

    
    private val transportEngineCoordinator = TransportEngineCoordinator()

    private suspend fun startTun2Socks(vpnInterface: ParcelFileDescriptor, proxyPort: Int) {
        try {
            transportEngineCoordinator.start(vpnInterface, proxyPort, proxySecret, serviceScope) { e ->
                VpnRuntimeState.updateState(VpnLifecycleState.ERROR, "Transport engine error: ${e.localizedMessage}")
                recoveryCoordinator.triggerRestart()
            }
        } catch (e: Exception) {
            if (e !is CancellationException) {
                VpnRuntimeState.updateState(VpnLifecycleState.FAILED, "Transport engine init failed: ${e.localizedMessage}")
            }
            throw e
        }
    }

    private fun stopTun2Socks() {
        transportEngineCoordinator.stop()
    }

    private fun stopVpn() {
        serviceScope.launch {
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
        stopDynamicNotification()
        Log.d("PinkVpnService", "Executing synchronized stop sequence...")

        try {
            _isRunning.value = false
            VpnRuntimeState.updateState(VpnLifecycleState.STOPPING)

            healthMonitor?.stop()

            

            DnsCacheManager.save(this@PinkVpnService)

            stopTun2Socks()
            proxyServer?.stop()
            proxyServer = null

            ServiceChecker.stopChecking()
            DpiEngine.stop()
            RobustResolver.stopBackgroundProber()
            CensorshipExpert.stop()
            PrefetchManager.stop()
            AutoTtlProber.stopProbing()
            DnsProtocols.clearPool()
            UdpTransportHandler.clearBuffers()
            RecoveryStateMachine.stop()
            RuntimeCoordinator.shutdown(this@PinkVpnService)
            DeviceMonitor.stopDeviceMonitoring(this@PinkVpnService)

            VpnSessionManager.stopSession()

            com.aistudio.pinkproxy.fresh.cronet.CronetEngineProvider.close()

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
        }
    }

    override fun onRevoke() {
        super.onRevoke()
        stopVpn()
    }

    fun restartProxyServer() {
        serviceScope.launch(ProxyDispatcher.io) {
            serviceLock.withLock {
                if (isStopping || !_isRunning.value) return@withLock
                try {
                    proxyServer?.stop()
                    proxyServer = null
                    delay(250)
                    proxyServer = PinkProxyServer(this@PinkVpnService, PROXY_PORT, proxySecret)
                    proxyServer?.start(VpnSessionManager.currentSession?.dataPlaneScope?.coroutineContext?.get(kotlinx.coroutines.Job))
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
        instance = null
        val appContext = applicationContext
        serviceScope.cancel()
        ProxyDispatcher.cancelAllBackgroundJobs()
        PrefetchManager.stop()
        healthMonitor?.stop()
        vpnNetworkMonitor?.stop()
        vpnNetworkMonitor = null

        // Non-blocking asynchronous coordinated shutdown prevents Main-Thread stalling and ANR
        VpnShutdownCoordinator.shutdownAsync(
            context = appContext,
            onBeforeAsync = {
                stopTun2Socks()
                vpnTunnelManager?.close()
                try {
                    if (wakeLock?.isHeld == true) wakeLock?.release()
                    if (wifiLock?.isHeld == true) wifiLock?.release()
                } catch (e: Exception) {
                    Log.v("PinkVpnService", "Lock release note: ${e.message}")
                }
                notificationController.stopNotification()
                updateTile(appContext)
                VpnRuntimeState.updateState(VpnLifecycleState.IDLE)
            },
            timeoutMs = 2000L,
            onComplete = {
                VpnSessionManager.stopSession()
                serviceScope.cancel()
                ProxyDispatcher.cancelAllBackgroundJobs()
                BypassConfig.activeVpnService = null
                ProxyDispatcher.context = null
            }
        )
    }
}
