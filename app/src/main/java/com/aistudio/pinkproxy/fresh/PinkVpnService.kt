package com.aistudio.pinkproxy.fresh

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.net.InetAddress
import android.content.pm.ServiceInfo
import android.content.ComponentName
import android.service.quicksettings.TileService

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
    
    private var vpnTunnelManager: VpnTunnelManager? = null
    private var vpnNetworkMonitor: VpnNetworkMonitor? = null
    
    private var proxyServer: PinkProxyServer? = null
    
    private var connectivityManager: android.net.ConnectivityManager? = null
    
    private var watchdogJob: Job? = null
    private var engineMonitorJob: Job? = null
    private var memoryMonitorJob: Job? = null
    private var chaffJob: Job? = null
    
    private var wakeLock: android.os.PowerManager.WakeLock? = null
    private var wifiLock: android.net.wifi.WifiManager.WifiLock? = null

    override fun onCreate() {
        super.onCreate()
        instance = this
        BypassConfig.activeVpnService = this
        ProxyDispatcher.context = this
        
        VpnNotificationManager.createNotificationChannel(this)
        vpnTunnelManager = VpnTunnelManager(this)
        
        val pm = getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
        wakeLock = pm.newWakeLock(android.os.PowerManager.PARTIAL_WAKE_LOCK, "PinkProxy:VpnWakeLock")
        
        val wm = getSystemService(Context.WIFI_SERVICE) as android.net.wifi.WifiManager
        wifiLock = wm.createWifiLock(android.net.wifi.WifiManager.WIFI_MODE_FULL_HIGH_PERF, "PinkProxy:WifiLock")
        
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
        
        BypassConfig.startDeviceMonitoring(this)
        PrefetchManager.start(this, this)
        DnsCacheManager.load(this)
        BypassConfig.loadTuningSettings(this)
        loadFilterSettings(this)
        
        registerNetworkMonitor()
        startMemoryMonitor()
        
        engineScope.launch {
            var lastMtu = BypassConfig.currentMtu.value
            BypassConfig.currentMtu.collect { newMtu ->
                if (_isRunning.value && vpnTunnelManager?.isEstablished() == true) {
                    val diff = Math.abs(newMtu - lastMtu)
                    if (diff >= 32) {
                        ProxyStats.logRecovery("Network Optimization: MTU changed to $newMtu. Re-establishing tunnel.")
                        lastMtu = newMtu
                        val restartIntent = Intent(this@PinkVpnService, PinkVpnService::class.java).apply {
                            action = "RESTART"
                        }
                        startService(restartIntent)
                    }
                }
            }
        }
    }

    private fun startWatchdog() {
        watchdogJob?.cancel()
        watchdogJob = engineScope.launch {
            var lastBytes = 0L
            var lastDnsFailures = 0L
            var stagnantCounter = 0
            while (isActive) {
                try {
                    // Adaptive watchdog: 90s if active, 180s if idle
                    val activeConns = ProxyStats.activeConnections.value
                    val delayMs = if (activeConns > 0) 90000L else 180000L
                    delay(delayMs)
                    
                    if (!_isRunning.value) continue
                    
                    val currentBytes = ProxyStats.bytesTransferred.value
                    val dnsFailures = ProxyStats.dnsFailureCount.value
                    
                    // Local check if proxy is alive (reduced frequency: only every ~5 mins)
                    if (proxyServer == null) {
                        ProxyStats.logRecovery("Watchdog: Proxy server missing! Starting...")
                        proxyServer = PinkProxyServer(this@PinkVpnService, PROXY_PORT, proxySecret)
                        proxyServer?.start()
                    } else if (System.currentTimeMillis() % 300000 < delayMs) { // Every 5 mins
                        val s = java.net.Socket()
                    try {
                        s.connect(java.net.InetSocketAddress("127.0.0.1", PROXY_PORT), 1000)
                        s.close()
                        
                        // If proxy is alive, also run background diagnostic occasionally
                        if (System.currentTimeMillis() % 600000 < delayMs) {
                            engineScope.launch {
                                try {
                                    val health = DiagnosticManager.runFullDiagnostic()
                                    if (!health.tcpOk || !health.dnsOk) {
                                        ProxyStats.logRecovery("Health Warning: ${health.recommendation}")
                                    }
                                } catch (e: Exception) {
                                    if (e is CancellationException) throw e
                                    Log.e("PinkVpnService", "Diagnostic check failed: ${e.message}")
                                }
                            }
                        }
                    } catch (e: java.io.IOException) {
                        ProxyStats.logRecovery("Watchdog: Proxy server unresponsive (${e.message}). Restarting...")
                        stopVpnInternal()
                        delay(500)
                        startVpnInternal()
                    } catch (e: Exception) {
                        if (e is CancellationException) throw e
                        Log.e("PinkVpnService", "Watchdog diagnostic error", e)
                    } finally {
                        try { s.close() } catch (e: Exception) {}
                    }
                    }
                    
                    if (dnsFailures > lastDnsFailures + 10) {
                        ProxyStats.logRecovery("Watchdog: High DNS failure rate detected ($dnsFailures). Optimizing resolver...")
                        RobustResolver.clearCache()
                    }
                    
                    lastBytes = currentBytes
                    lastDnsFailures = dnsFailures
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.e("PinkVpnService", "Watchdog loop error", e)
                } catch (e: Throwable) {
                    Log.e("PinkVpnService", "Critical Watchdog error", e)
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
                    
                    // If VPN is active, we might need to restart sockets to bind to the new interface
                    if (_isRunning.value) {
                        engineScope.launch {
                            delay(1500) // Wait for network stability
                            if (_isRunning.value) {
                                ProxyStats.logRecovery("Network transition detected. Refreshing VPN tunnel.")
                                startVpn() // Intelligent restart (handles internal state)
                            }
                        }
                    }
                }
            },
            capabilitiesChangeCallback = { network, capabilities ->
                if (capabilities.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                    Log.i("PinkVpnService", "Network validated: $network")
                }
                val isWifi = capabilities.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI)
                val isMobile = capabilities.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR)
                
                if (isWifi && _isRunning.value) {
                    try { 
                        if (wifiLock?.isHeld == false) wifiLock?.acquire() 
                    } catch(e: Exception) {
                        Log.v("PinkVpnService", "WifiLock acquire error: ${e.message}")
                    }
                } else {
                    try { 
                        if (wifiLock?.isHeld == true) wifiLock?.release() 
                    } catch(e: Exception) {
                        Log.v("PinkVpnService", "WifiLock release error: ${e.message}")
                    }
                }
                
                BypassConfig.updateNetworkType(if (isWifi) NetworkType.WIFI else if (isMobile) NetworkType.MOBILE else NetworkType.NONE)
            }
        )
        vpnNetworkMonitor?.start()
    }

    private fun startChaffGenerator() {
        chaffJob?.cancel()
        chaffJob = engineScope.launch {
            val rnd = java.util.concurrent.ThreadLocalRandom.current()
            val decoys = listOf("google.com", "cloudflare.com", "microsoft.com", "wikipedia.org")
            while (isActive) {
                val delayMs = if (BypassConfig.isPanicMode) rnd.nextLong(15000, 30000) else rnd.nextLong(45000, 90000)
                delay(delayMs)
                if (!_isRunning.value) break
                
                if (BypassConfig.isPanicMode || ProxyStats.censorshipIntensity.value > 60) {
                    try {
                        val decoy = decoys[rnd.nextInt(decoys.size)]
                        DnsProtocols.queryUdpDnsShadow(decoy, "1.1.1.1", this@PinkVpnService)
                    } catch (e: Exception) {
                        Log.v("PinkVpnService", "Chaff packet error: ${e.message}")
                    }
                }
            }
        }
    }

    private fun startMemoryMonitor() {
        memoryMonitorJob?.cancel()
        memoryMonitorJob = engineScope.launch {
            while (isActive) {
                delay(60000) // Check every minute
                val rt = Runtime.getRuntime()
                val used = (rt.totalMemory() - rt.freeMemory()) / 1024 / 1024
                val max = rt.maxMemory() / 1024 / 1024
                val percent = (used.toDouble() / max * 100).toInt()
                
                if (percent > 85) {
                    Log.w("PinkVpnService", "CRITICAL MEMORY: $percent% ($used MB / $max MB). Triggering emergency cleanup.")
                    ProxyStats.logRecovery("System: High memory pressure ($percent%). Clearing caches.")
                    DnsCacheManager.clearAll()
                    UdpTransportHandler.clearBuffers()
                    ProxyStats.releaseAllPools()
                    System.gc()
                    
                    if (percent > 92 && _isRunning.value) {
                         Log.e("PinkVpnService", "MEMORY EXHAUSTED ($percent%). Restarting VPN session.")
                         ProxyStats.logRecovery("System: Memory exhausted. Emergency session restart.")
                         
                         // Re-use the existing RESTART action logic
                         val restartIntent = Intent(this@PinkVpnService, PinkVpnService::class.java).apply {
                             action = "RESTART"
                         }
                         startService(restartIntent)
                    }
                }
            }
        }
    }

    private val serviceLock = kotlinx.coroutines.sync.Mutex()
    @Volatile private var isStopping = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        showNotification()
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
                        Log.e("PinkVpnService", "Stop service error", e)
                    } catch (e: Throwable) {
                        Log.e("PinkVpnService", "Critical Stop service error", e)
                    }
                }
            }
            return START_NOT_STICKY
        }
        
        if (action == "CHANGE_STRATEGY") {
            engineScope.launch {
                try {
                    ProxyStats.logRecovery("Strategy Changed: Applied dynamically & instantly")
                    showNotification()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.e("PinkVpnService", "Change strategy error", e)
                } catch (e: Throwable) {
                    Log.e("PinkVpnService", "Critical Change strategy error", e)
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
                        delay(500) // Gap for OS cleanup
                        showNotification()
                        startVpnInternal()
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        Log.e("PinkVpnService", "Restart internal error", e)
                    } catch (e: Throwable) {
                        Log.e("PinkVpnService", "Critical Restart internal error", e)
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
                    Log.e("PinkVpnService", "Start action error", e)
                    VpnRuntimeState.updateState(VpnLifecycleState.FAILED, "Start failed: ${e.message}")
                } catch (e: Throwable) {
                    Log.e("PinkVpnService", "Critical Start error", e)
                    VpnRuntimeState.updateState(VpnLifecycleState.FAILED, "Critical Start failure")
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
                } catch (e: Throwable) {
                    Log.e("PinkVpnService", "Start internal error", e)
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
            ServiceChecker.startChecking(engineScope, this@PinkVpnService)
            RobustResolver.initialize(engineScope)
            RobustResolver.startDnsOptimizer(engineScope, this@PinkVpnService)
            DpiEngine.start(this@PinkVpnService)
            CensorshipExpert.start()
            RecoveryManager.startHealthCheck(engineScope)
            
            proxyServer = PinkProxyServer(this@PinkVpnService, PROXY_PORT, proxySecret)
            proxyServer?.start()
            
            startWatchdog()
            
            sessionScope?.cancel()
            sessionScope = CoroutineScope(ProxyDispatcher.io + SupervisorJob())
            
            val dnsServers = when (BypassConfig.dnsType) {
                DnsType.GOOGLE_DOH -> listOf("8.8.8.8", "8.8.4.4")
                DnsType.CLOUDFLARE_DOH -> listOf("1.1.1.1", "1.0.0.1")
                DnsType.QUAD9_DOH -> listOf("9.9.9.9", "149.112.112.112")
                DnsType.CUSTOM_UDP -> listOf(BypassConfig.customDnsUrl)
                else -> listOf("1.1.1.1", "8.8.8.8")
            }

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
                Log.w("PinkVpnService", "Failed with IPv6/Full config, retrying IPv4 basic: ${e.message}")
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

            // Dynamically discover optimal TTL for DPI bypass
            AutoTtlProber.startProbing(engineScope, this@PinkVpnService)

            try {
                wakeLock?.acquire(24 * 60 * 60 * 1000L) // 24h max
            } catch (e: Exception) {
                Log.e("PinkVpnService", "Failed to acquire wakeLock: ${e.message}")
            }

            _isRunning.value = true
            
            startTun2Socks(pfd, PROXY_PORT)
            
            engineMonitorJob?.cancel()
            engineMonitorJob = engineScope.launch {
                while (isActive && _isRunning.value) {
                    delay(30000)
                    if (_isRunning.value && vpnTunnelManager?.isEstablished() == true) {
                        try {
                            val s = java.net.Socket()
                            s.connect(java.net.InetSocketAddress("127.0.0.1", PROXY_PORT), 1500)
                            s.close()
                        } catch (e: Exception) {
                            Log.e("PinkVpnService", "Engine health check failed: ${e.message}. Restarting...")
                            ProxyStats.recordDpiEvent(DpiType.CONNECTION_TIMEOUT)
                            withContext(Dispatchers.Main) {
                                VpnRuntimeState.updateState(VpnLifecycleState.RECOVERING, "Engine health check failed. Attempting recovery...")
                                stopVpn()
                                startVpn()
                            }
                        }
                    }
                }
            }
            
            startChaffGenerator()
            startSessionWarmup()
            VpnRuntimeState.updateState(VpnLifecycleState.RUNNING)
            VpnRuntimeState.clearError()
        } catch (e: Exception) {
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
                } catch (e: Throwable) {
                    Log.e("PinkVpnService", "Critical tun2socks run-time error", e)
                    VpnRuntimeState.updateState(VpnLifecycleState.ERROR, "Transport engine crashed")
                }
            }
            Log.i("PinkVpnService", "tun2socks started on fd $fd")
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e("PinkVpnService", "Failed to start tun2socks", e)
            VpnRuntimeState.updateState(VpnLifecycleState.FAILED, "Transport engine init failed: ${e.localizedMessage}")
        } catch (e: Throwable) {
            Log.e("PinkVpnService", "Critical tun2socks start error", e)
            VpnRuntimeState.updateState(VpnLifecycleState.FAILED, "Transport engine critical failure")
        }
    }

    private fun stopTun2Socks() {
        try {
            engine.Engine.stop()
        } catch (e: Throwable) {
            Log.e("PinkVpnService", "Failed to stop tun2socks", e)
        }
    }

    private fun showNotification() {
        val notification = VpnNotificationManager.buildNotification(this, "Engine Active", "Automated DPI Evasion & Smart Proxy active")

        try {
            if (Build.VERSION.SDK_INT >= 34) {
                try {
                    startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
                } catch (e: android.app.ForegroundServiceStartNotAllowedException) {
                    Log.e("PinkVpnService", "Foreground service start not allowed: ${e.message}")
                    throw e
                } catch (e: Exception) {
                    Log.w("PinkVpnService", "Failed VPN foreground service type, trying default startForeground: ${e.message}")
                    startForeground(1, notification)
                }
            } else {
                startForeground(1, notification)
            }
        } catch (e: Exception) {
            Log.e("PinkVpnService", "startForeground failed: ${e.message}", e)
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
            Log.e("PinkVpnService", "Stop internal error", e)
        } catch (e: Throwable) {
            Log.e("PinkVpnService", "Critical Stop internal error", e)
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
            
            sessionScope?.cancel()
            sessionScope = null
            
            DnsCacheManager.save(this@PinkVpnService)
            
            watchdogJob?.cancel()
            watchdogJob = null
            engineMonitorJob?.cancel()
            engineMonitorJob = null
            memoryMonitorJob?.cancel()
            memoryMonitorJob = null
            chaffJob?.cancel()
            chaffJob = null
            
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

            try {
                if (Build.VERSION.SDK_INT >= 33) {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                } else {
                    @Suppress("DEPRECATION")
                    stopForeground(true)
                }
            } catch (e: Throwable) {
                try {
                    @Suppress("DEPRECATION")
                    stopForeground(true)
                } catch (ex: Throwable) {}
            }
            
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

    override fun onDestroy() {
        super.onDestroy()
        PrefetchManager.stop()
        DnsCacheManager.save(this)
        
        runBlocking {
            try {
                withTimeout(2000) {
                    stopVpnInternal()
                }
            } catch (e: Throwable) {
                Log.e("PinkVpnService", "Shutdown timed out or failed", e)
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
