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
        @JvmStatic val selectedPackages = mutableSetOf<String>()
        
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
            } catch (e: Throwable) {}
        }
    }

    val engineScope = CoroutineScope(ProxyDispatcher.io + SupervisorJob() + ProxyDispatcher.globalHandler)
    private var sessionScope: CoroutineScope? = null
    
    fun getServiceScope(): CoroutineScope = engineScope
    
    private var vpnInterface: ParcelFileDescriptor? = null
    private var proxyServer: PinkProxyServer? = null
    
    private var connectivityManager: android.net.ConnectivityManager? = null
    private var networkCallback: android.net.ConnectivityManager.NetworkCallback? = null
    
    private var watchdogJob: Job? = null
    private var engineMonitorJob: Job? = null
    
    private var wakeLock: android.os.PowerManager.WakeLock? = null
    private var wifiLock: android.net.wifi.WifiManager.WifiLock? = null

    override fun onCreate() {
        super.onCreate()
        instance = this
        BypassConfig.activeVpnService = this
        ProxyDispatcher.context = this
        
        val pm = getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
        wakeLock = pm.newWakeLock(android.os.PowerManager.PARTIAL_WAKE_LOCK, "PinkProxy:VpnWakeLock")
        
        val wm = getSystemService(Context.WIFI_SERVICE) as android.net.wifi.WifiManager
        wifiLock = wm.createWifiLock(android.net.wifi.WifiManager.WIFI_MODE_FULL_HIGH_PERF, "PinkProxy:WifiLock")
        
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
        
        DnsCacheManager.load(this)
        BypassConfig.loadTuningSettings(this)
        loadFilterSettings(this)
        
        registerNetworkMonitor()
        
        engineScope.launch {
            var lastMtu = BypassConfig.currentMtu.value
            BypassConfig.currentMtu.collect { newMtu ->
                if (_isRunning.value && vpnInterface != null) {
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
                    } else if (System.currentTimeMillis() % 300000 < delayMs) {
                        try {
                            val s = java.net.Socket()
                            s.connect(java.net.InetSocketAddress("127.0.0.1", PROXY_PORT), 1000)
                            s.close()
                        } catch (e: Throwable) {
                            ProxyStats.logRecovery("Watchdog: Proxy server unresponsive. Restarting...")
                            stopVpnInternal()
                            delay(500)
                            startVpnInternal()
                        }
                    }
                    
                    // Throttling detection
                    if (currentBytes > lastBytes && currentBytes - lastBytes < 5000 && activeConns > 2) {
                        stagnantCounter++
                        if (stagnantCounter >= 3) {
                            ProxyStats.logRecovery("Watchdog: Data flow stagnant. Attempting recovery...")
                            stagnantCounter = 0
                            RecoveryManager.handleEvent(RecoveryEvent.TCP_STALL, "Flow < 5KB over 90s with active connections")
                        }
                    } else {
                        stagnantCounter = 0
                    }
                    
                    if (dnsFailures > lastDnsFailures + 10) {
                        ProxyStats.logRecovery("Watchdog: High DNS failure rate detected ($dnsFailures). Optimizing resolver...")
                        RobustResolver.clearCache()
                    }
                    
                    lastBytes = currentBytes
                    lastDnsFailures = dnsFailures
                } catch (e: CancellationException) {
                    break
                } catch (e: Throwable) {
                    Log.e("PinkVpnService", "Watchdog error", e)
                }
            }
        }
    }

    private fun registerNetworkMonitor() {
        try {
            val request = android.net.NetworkRequest.Builder()
                .addCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()
            networkCallback = object : android.net.ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: android.net.Network) {
                    Log.i("PinkVpnService", "Network available: $network")
                    try { setUnderlyingNetworks(arrayOf(network)) } catch (e: Throwable) {}
                    DnsCacheManager.onNetworkChanged()
                    RobustResolver.clearCache()
                }

                override fun onLost(network: android.net.Network) {
                    Log.i("PinkVpnService", "Network lost: $network")
                    try { setUnderlyingNetworks(null) } catch (e: Throwable) {}
                    DnsCacheManager.onNetworkChanged()
                    RobustResolver.clearCache()
                }

                override fun onCapabilitiesChanged(network: android.net.Network, capabilities: android.net.NetworkCapabilities) {
                    if (capabilities.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                        Log.i("PinkVpnService", "Network validated: $network")
                    }
                    val isWifi = capabilities.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI)
                    val isMobile = capabilities.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR)
                    
                    if (isWifi && _isRunning.value) {
                        try { if (wifiLock?.isHeld == false) wifiLock?.acquire() } catch(e: Throwable) {}
                    } else {
                        try { if (wifiLock?.isHeld == true) wifiLock?.release() } catch(e: Throwable) {}
                    }
                    
                    BypassConfig.updateNetworkType(if (isWifi) NetworkType.WIFI else if (isMobile) NetworkType.MOBILE else NetworkType.UNKNOWN)
                }
            }
            networkCallback?.let {
                connectivityManager?.registerDefaultNetworkCallback(it)
            }
        } catch (e: Throwable) {
            Log.e("PinkVpnService", "Failed to register network monitor", e)
        }
    }

    private fun startChaffGenerator() {
        // Disabled background traffic generator to save bandwidth and battery
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
                    } catch (e: Throwable) {
                        Log.e("PinkVpnService", "Stop error", e)
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
                } catch (e: Throwable) {
                    Log.e("PinkVpnService", "Change strategy error", e)
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
                    } catch (e: Throwable) {
                        Log.e("PinkVpnService", "Restart error", e)
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
                } catch (e: Throwable) {
                    Log.e("PinkVpnService", "Start error", e)
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
            DpiEngine.start(this@PinkVpnService)
            CensorshipExpert.start()
            RecoveryManager.startHealthCheck(engineScope)
            
            proxyServer = PinkProxyServer(this@PinkVpnService, PROXY_PORT, proxySecret)
            proxyServer?.start()
            
            startWatchdog()
            
            sessionScope?.cancel()
            sessionScope = CoroutineScope(ProxyDispatcher.io + SupervisorJob())
            
            val builder = Builder()
            builder.setSession("PinkProxy VPN")
            builder.setMtu(BypassConfig.currentMtu.value)
            builder.addAddress("10.0.0.1", 30)
            builder.addRoute("0.0.0.0", 0)
            
            try {
                builder.addAddress("fd00::1", 126)
                builder.addRoute("::", 0)
            } catch (e: Throwable) {
                Log.w("PinkVpnService", "Failed to add IPv6 route", e)
            }

            // Exclude or include packages
            if (isExcludeMode) {
                builder.addDisallowedApplication(packageName)
                selectedPackages.forEach { pkg ->
                    try { builder.addDisallowedApplication(pkg) } catch (e: Throwable) { android.util.Log.v("PinkVpn", "Ignored app config: ${e.message}") }
                }
            } else {
                selectedPackages.filter { it != packageName }.forEach { pkg ->
                    try { builder.addAllowedApplication(pkg) } catch (e: Throwable) { android.util.Log.v("PinkVpn", "Ignored app config: ${e.message}") }
                }
            }

            try {
                vpnInterface = builder.establish()
            } catch (e: SecurityException) {
                Log.e("PinkVpnService", "SecurityException: VPN is not prepared or permission was revoked", e)
                VpnRuntimeState.updateState(VpnLifecycleState.IDLE)
                stopVpnInternal()
                return@withContext
            } catch (e: Throwable) {
                Log.e("PinkVpnService", "Failed to establish VPN interface due to system error", e)
                VpnRuntimeState.updateState(VpnLifecycleState.IDLE)
                stopVpnInternal()
                return@withContext
            }

            if (vpnInterface == null) {
                Log.e("PinkVpnService", "Failed to establish VPN interface (returned null)")
                stopVpnInternal()
                return@withContext
            }

            // Dynamically discover optimal TTL for DPI bypass
            AutoTtlProber.startProbing(engineScope, this@PinkVpnService)

            try {
                wakeLock?.acquire(24 * 60 * 60 * 1000L) // 24h max
            } catch (e: Throwable) {}

            proxyServer?.start() // Ensure proxy is running
            _isRunning.value = true
            
            // Start tun2socks
        vpnInterface?.let {
            startTun2Socks(it, PROXY_PORT)
        } ?: Log.e("PinkVpnService", "VPN interface is null, cannot start tun2socks")
            
            // Monitor engine status
            engineMonitorJob?.cancel()
            engineMonitorJob = engineScope.launch {
                while (isActive && _isRunning.value) {
                    delay(30000)
                    if (_isRunning.value && vpnInterface != null) {
                        try {
                            val s = java.net.Socket()
                            s.connect(java.net.InetSocketAddress("127.0.0.1", PROXY_PORT), 1500)
                            s.close()
                        } catch (e: Throwable) {
                            Log.e("PinkVpnService", "Engine health check failed: ${e.message}. Restarting...")
                            ProxyStats.recordDpiEvent(DpiType.CONNECTION_TIMEOUT)
                            withContext(Dispatchers.Main) {
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
        } catch (e: Throwable) {
            Log.e("PinkVpnService", "Error starting VPN", e)
            VpnRuntimeState.updateState(VpnLifecycleState.FAILED)
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
            key.setDevice("fd://${vpnInterface.fd}")
            key.setLogLevel("info")
            engine.Engine.insert(key)
            engineScope.launch {
                try {
                    engine.Engine.start()
                    Log.i("PinkVpnService", "tun2socks stopped naturally")
                } catch (e: Throwable) {
                    Log.e("PinkVpnService", "tun2socks error", e)
                }
            }
            Log.i("PinkVpnService", "tun2socks started on fd ${vpnInterface.fd}")
        } catch (e: Throwable) {
            Log.e("PinkVpnService", "Failed to start tun2socks", e)
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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                "pink_proxy_channel",
                "PinkProxy Service",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }

        val launchIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, launchIntent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        val stopIntent = Intent(this, PinkVpnService::class.java).apply { action = "STOP" }
        val stopPendingIntent = PendingIntent.getService(this, 1, stopIntent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)

        val notification = NotificationCompat.Builder(this, "pink_proxy_channel")
            .setContentTitle("PinkProxy DPI Engine Active")
            .setContentText("Automated DPI Evasion & Smart Proxy active")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pendingIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "STOP", stopPendingIntent)
            .setOngoing(true)
            .build()

        try {
            if (Build.VERSION.SDK_INT >= 34) {
                try {
                    val specialUseType = 0x40000000
                    startForeground(1, notification, specialUseType)
                } catch (e: Throwable) {
                    startForeground(1, notification)
                }
            } else {
                startForeground(1, notification)
            }
        } catch (e: Throwable) {
            Log.e("PinkVpnService", "startForeground failed: ${e.message}")
            try { startForeground(1, notification) } catch(ex: Throwable) {}
        }
    }

    private fun stopVpn() {
        engineScope.launch {
            serviceLock.withLock {
                try {
                    stopVpnInternal()
                } catch (e: Throwable) {
                    Log.e("PinkVpnService", "Stop internal error", e)
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
            VpnRuntimeState.updateState(VpnLifecycleState.IDLE)
            DnsCacheManager.save(this@PinkVpnService)
            
            watchdogJob?.cancel()
            watchdogJob = null
            engineMonitorJob?.cancel()
            engineMonitorJob = null
            
            stopTun2Socks()
            proxyServer?.stop()
            proxyServer = null
            
            ServiceChecker.stopChecking()
            DpiEngine.stop()
            CensorshipExpert.stop()
            DnsProtocols.clearPool()
            UdpTransportHandler.clearBuffers()
            RecoveryManager.stopHealthCheck()
            
            try {
                vpnInterface?.let {
                    it.close()
                    Log.i("PinkVpnService", "TUN Interface released")
                }
            } catch (e: Throwable) {
                Log.e("PinkVpnService", "Interface close error", e)
            } finally {
                vpnInterface = null
            }

            sessionScope?.cancel()
            sessionScope = null
            
            try {
                if (wakeLock?.isHeld == true) wakeLock?.release()
                if (wifiLock?.isHeld == true) wifiLock?.release()
            } catch (e: Throwable) {}

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
        
        try {
            networkCallback?.let { connectivityManager?.unregisterNetworkCallback(it) }
        } catch (e: Throwable) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        
        engineScope.cancel()
        instance = null
        BypassConfig.activeVpnService = null
        ProxyDispatcher.context = null
    }
}
