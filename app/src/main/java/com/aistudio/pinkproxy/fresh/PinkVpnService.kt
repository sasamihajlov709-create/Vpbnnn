package com.aistudio.pinkproxy.fresh

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.util.Log
import java.net.InetSocketAddress
import java.net.Socket
import androidx.core.app.NotificationCompat
import androidx.core.content.edit
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

class PinkVpnService : VpnService() {

    companion object {
        private val _isRunning = MutableStateFlow(false)
        val isRunning: StateFlow<Boolean> = _isRunning

        var selectedPackages: MutableSet<String> = java.util.concurrent.CopyOnWriteArraySet<String>()
        @Volatile var isExcludeMode = true
        var instance: PinkVpnService? = null

        fun saveFilterSettings(context: Context) {
            val prefs = context.getSharedPreferences("pink_proxy_filter", Context.MODE_PRIVATE)
            prefs.edit {
                putStringSet("selected_packages", selectedPackages)
                putBoolean("is_exclude_mode", isExcludeMode)
            }
        }

        fun loadFilterSettings(context: Context) {
            val prefs = context.getSharedPreferences("pink_proxy_filter", Context.MODE_PRIVATE)
            val saved = prefs.getStringSet("selected_packages", emptySet()) ?: emptySet()
            selectedPackages.clear()
            selectedPackages.addAll(saved)
            isExcludeMode = prefs.getBoolean("is_exclude_mode", true)
        }

        fun saveVpnState(context: Context, isRunning: Boolean) {
            val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
            prefs.edit {
                putBoolean("vpn_should_be_running", isRunning)
                putBoolean("vpn_was_active", isRunning)
            }
        }

        fun updateTile(context: Context) {
            android.service.quicksettings.TileService.requestListeningState(context, android.content.ComponentName(context, PinkProxyTileService::class.java))
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var proxyServer: PinkProxyServer? = null
    private val proxySecret = java.util.UUID.randomUUID().toString()
    private var serviceScope = CoroutineScope(ProxyDispatcher.io + SupervisorJob())
    fun getServiceScope(): CoroutineScope = serviceScope
    private var sessionScope: CoroutineScope? = null
    private var mtuJob: Job? = null
    private val PROXY_PORT = 18080
    private var connectivityManager: android.net.ConnectivityManager? = null
    private var networkCallback: android.net.ConnectivityManager.NetworkCallback? = null

    private var watchdogJob: Job? = null

    private var engineMonitorJob: Job? = null

    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: android.net.wifi.WifiManager.WifiLock? = null

    override fun onCreate() {
        super.onCreate()
        instance = this
        ProxyDispatcher.context = applicationContext
        
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "PinkProxy:VpnLock").apply {
            setReferenceCounted(false)
            acquire(10 * 60 * 1000L)
        }
        
        val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as android.net.wifi.WifiManager
        val wifiMode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            android.net.wifi.WifiManager.WIFI_MODE_FULL_LOW_LATENCY
        } else {
            @Suppress("DEPRECATION")
            android.net.wifi.WifiManager.WIFI_MODE_FULL_HIGH_PERF
        }
        wifiLock = wm.createWifiLock(wifiMode, "PinkProxy:WifiLock").apply {
            setReferenceCounted(false)
        }

        BypassConfig.activeVpnService = this
        DnsCacheManager.load(this)
        BypassConfig.loadTuningSettings(this)
        loadFilterSettings(this)

        mtuJob = serviceScope.launch {
            BypassConfig.currentMtu.collect { newMtu ->
                if (_isRunning.value && vpnInterface != null) {
                    Log.i("PinkVpn", "Dynamic MTU changed to $newMtu. Hot-restarting interface.")
                    withContext(Dispatchers.Main) {
                        stopVpn()
                        startVpn()
                    }
                }
            }
        }
        
        // Start proxy server with session secret
        proxyServer = PinkProxyServer(this, PROXY_PORT, proxySecret)
        proxyServer?.start()

        RobustResolver.initialize(serviceScope)
        RobustResolver.startDnsOptimizer(serviceScope, this)
        BypassConfig.startAutonomousOptimizer(serviceScope, this)
        BypassConfig.startLearningTask(serviceScope)
        BypassConfig.startNetworkWeatherSensor(serviceScope)
        ServiceChecker.startChecking(serviceScope, this)
        RecoveryManager.startHealthCheck(serviceScope)
        DpiEngine.start(this)
        CensorshipExpert.start()
        
        serviceScope.launch {
            BypassConfig.currentMtu.collect { newMtu ->
                if (_isRunning.value && vpnInterface != null) {
                    ProxyStats.logRecovery("Network Optimization: MTU adjusted to $newMtu")
                    // Note: In Android, changing MTU often requires re-establishing the VPN interface.
                    // We only do this if the change is significant to avoid frequent drops.
                    // For small changes, TcpTransportHandler's MSS clamping handles it.
                }
            }
        }

        registerNetworkMonitor()
        startWatchdog()
    }

    private fun startWatchdog() {
        watchdogJob?.cancel()
        watchdogJob = serviceScope.launch {
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
                            ProxyStats.logRecovery("Watchdog: Proxy port $PROXY_PORT dead. Restarting engine...")
                            RecoveryManager.handleEvent(RecoveryEvent.PROXY_UNREACHABLE, "Engine port dead")
                            proxyServer?.stop()
                            proxyServer = PinkProxyServer(this@PinkVpnService, PROXY_PORT, proxySecret)
                            proxyServer?.start()
                        }
                    }

                    // DNS health check (more tolerant)
                    if (dnsFailures > lastDnsFailures + 20) {
                        ProxyStats.logRecovery("Watchdog: High DNS failures (${dnsFailures - lastDnsFailures}). Flushing resolver.")
                        RobustResolver.clearCache()
                    }
                    lastDnsFailures = dnsFailures
                    
                    if (currentBytes > 0 && currentBytes == lastBytes && activeConns > 0) {
                        stagnantCounter++
                        if (stagnantCounter >= 2) { // ~3-6 minutes of stagnant active connections
                            ProxyStats.logRecovery("Watchdog: Tunnel stagnation detected.")
                            stagnantCounter = 0
                            RecoveryManager.handleEvent(RecoveryEvent.TUNNEL_STALL, "Active but stagnant")
                        }
                    } else {
                        stagnantCounter = 0
                    }
                    lastBytes = currentBytes
                } catch (e: kotlinx.coroutines.CancellationException) {
                    throw e
                } catch (e: Throwable) {
                    android.util.Log.e("PinkVpnService", "Watchdog error", e)
                }
            }
        }
    }

    private fun registerNetworkMonitor() {
        try {
            connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
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
            connectivityManager?.registerDefaultNetworkCallback(networkCallback!!)
        } catch (e: Throwable) {
            Log.e("PinkVpnService", "Failed to register network monitor", e)
        }
    }

    private fun startChaffGenerator() {
        // Disabled background traffic generator to save bandwidth and battery
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        showNotification()
        val action = intent?.action
        if (action == "STOP") {
            saveVpnState(this, false)
            stopVpn()
            _isRunning.value = false
            VpnRuntimeState.updateState(VpnLifecycleState.STOPPING)
            stopSelf()
            return START_NOT_STICKY
        }
        if (action == "RESTART" || action == "CHANGE_STRATEGY") {
            serviceScope.launch {
                ProxyStats.logRecovery(if (action == "RESTART") "Core System Re-Started" else "Strategy Changed: Restarting engine")
            }
            stopVpn()
            startVpn()
            return START_STICKY
        }

        saveVpnState(this, true)
        VpnRuntimeState.updateState(VpnLifecycleState.STARTING)
        startVpn()
        updateTile(this)
        return START_STICKY
    }

    private fun startVpn() {
        if (vpnInterface != null) return

        try {
            val mtu = BypassConfig.currentMtu.value
            val builder = Builder()
                .setSession("PinkProxy")
                .setMtu(mtu)
                .addAddress("10.0.0.2", 24)
                .addAddress("fd00:1:fd00:1:fd00:1:fd00:1", 128)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .addDnsServer("2606:4700:4700::1111")
                .addDnsServer("2001:4860:4860::8888")

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                builder.setUnderlyingNetworks(null)
            }

            // Route all traffic
            builder.addRoute("0.0.0.0", 0)
            try {
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

            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                Log.e("PinkVpnService", "Failed to establish VPN interface")
                stopVpn()
                return
            }

            // Dynamically discover optimal TTL for DPI bypass
            AutoTtlProber.startProbing(serviceScope, this)

            try {
                wakeLock?.acquire(24 * 60 * 60 * 1000L) // 24h max
            } catch (e: Throwable) {}

            proxyServer?.start() // Ensure proxy is running
            _isRunning.value = true
            
            // Start tun2socks
            startTun2Socks(vpnInterface!!, PROXY_PORT)
            
            // Monitor engine status
            engineMonitorJob?.cancel()
            engineMonitorJob = serviceScope.launch {
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
        serviceScope.launch {
            delay(2000)
            val importantHosts = listOf(
                "google.com", "telegram.org", "github.com", "youtube.com", "googlevideo.com"
            )
            importantHosts.forEach { host ->
                if (!_isRunning.value) return@launch
                try {
                    RobustResolver.resolve(host, this@PinkVpnService)
                } catch (e: Throwable) {}
            }
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
            serviceScope.launch {
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
            Log.i("PinkVpnService", "tun2socks stopped")
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
                    startForeground(1, notification, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
                } catch (e: Throwable) {
                    startForeground(1, notification)
                }
            } else {
                startForeground(1, notification)
            }
        } catch (e: Throwable) {
            Log.e("PinkVpnService", "Failed to start foreground service: ${e.message}")
        }
    }

    private fun stopVpn() {
        _isRunning.value = false
        VpnRuntimeState.updateState(VpnLifecycleState.IDLE)
        DnsCacheManager.save(this)
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
        
        try {
            networkCallback?.let { connectivityManager?.unregisterNetworkCallback(it) }
            networkCallback = null
        } catch (e: Throwable) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        
        try {
            if (wakeLock?.isHeld == true) wakeLock?.release()
            if (wifiLock?.isHeld == true) wifiLock?.release()
        } catch (e: Throwable) {}

        stopTun2Socks()
        proxyServer?.stop()
        
        watchdogJob?.cancel()
        watchdogJob = null
        engineMonitorJob?.cancel()
        engineMonitorJob = null
        
        try {
            vpnInterface?.close()
        } catch (e: Throwable) {
            Log.e("PinkVpnService", "Error closing VPN interface", e)
        }
        vpnInterface = null
        
        sessionScope?.cancel()
        sessionScope = null
        
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
        updateTile(this)
    }

    @Suppress("DEPRECATION")
    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level >= android.content.ComponentCallbacks2.TRIM_MEMORY_MODERATE) { 
            ProxyStats.logRecovery("System memory low (level $level). Aggressive cleanup...")
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
        stopVpn()
        try {
            networkCallback?.let { connectivityManager?.unregisterNetworkCallback(it) }
        } catch (e: Throwable) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        serviceScope.cancel()
        instance = null
        BypassConfig.activeVpnService = null
    }
}
