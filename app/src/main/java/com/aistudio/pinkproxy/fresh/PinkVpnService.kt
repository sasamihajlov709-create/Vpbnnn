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
import androidx.core.app.NotificationCompat
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
            prefs.edit().apply {
                putStringSet("selected_packages", selectedPackages)
                putBoolean("is_exclude_mode", isExcludeMode)
                apply()
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
            prefs.edit().putBoolean("vpn_should_be_running", isRunning).apply()
            prefs.edit().putBoolean("vpn_was_active", isRunning).apply()
        }

        fun updateTile(context: Context) {
            android.service.quicksettings.TileService.requestListeningState(context, android.content.ComponentName(context, PinkProxyTileService::class.java))
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var proxyServer: PinkProxyServer? = null
    private var serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    fun getServiceScope(): CoroutineScope = serviceScope
    private var sessionScope: CoroutineScope? = null
    private val PROXY_PORT = 18080
    private var connectivityManager: android.net.ConnectivityManager? = null
    private var networkCallback: android.net.ConnectivityManager.NetworkCallback? = null

    private var watchdogJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        instance = this
        BypassConfig.activeVpnService = this
        BypassConfig.loadTuningSettings(this)
        loadFilterSettings(this)
        
        // Start proxy server
        proxyServer = PinkProxyServer(this, PROXY_PORT)
        proxyServer?.start()
        
        RobustResolver.startBackgroundProber(serviceScope, this)
        ServiceChecker.startChecking(serviceScope, this)
        BypassConfig.startAutonomousOptimizer(serviceScope)

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
                delay(40000)
                if (!_isRunning.value) continue
                
                val currentBytes = ProxyStats.bytesTransferred.value
                val activeConns = ProxyStats.activeConnections.value
                val dnsFailures = ProxyStats.dnsFailureCount.value
                
                // Local check if proxy is alive
                try {
                    val s = java.net.Socket()
                    s.connect(java.net.InetSocketAddress("127.0.0.1", PROXY_PORT), 2000)
                    s.close()
                } catch (e: Exception) {
                    ProxyStats.logRecovery("Watchdog: Proxy port $PROXY_PORT is unreachable! Restarting proxy...")
                    proxyServer?.stop()
                    proxyServer = PinkProxyServer(this@PinkVpnService, PROXY_PORT)
                    proxyServer?.start()
                }

                // DNS health check
                if (dnsFailures > lastDnsFailures + 10) {
                    ProxyStats.logRecovery("Watchdog: High DNS failure rate detected. Clearing resolver cache.")
                    RobustResolver.clearCache()
                }
                lastDnsFailures = dnsFailures
                
                if (currentBytes > 0 && currentBytes == lastBytes && activeConns > 0) {
                    stagnantCounter++
                    if (stagnantCounter >= 3) { // 2 minutes of stagnant active connections
                        ProxyStats.logRecovery("Watchdog: Engine Stagnant detected. Self-healing...")
                        stagnantCounter = 0
                        RecoveryManager.handleEvent(RecoveryEvent.TUNNEL_STALL, "Zero traffic and proxy failure")
                        withContext(Dispatchers.Main) {
                            val intent = Intent(this@PinkVpnService, PinkVpnService::class.java).apply { action = "RESTART" }
                            startForegroundService(intent)
                        }
                    }
                } else {
                    stagnantCounter = 0
                }
                lastBytes = currentBytes
            }
        }
    }

    private fun registerNetworkMonitor() {
        try {
            connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
            networkCallback = object : android.net.ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: android.net.Network) {
                    Log.i("PinkVpnService", "Network available: $network")
                    RobustResolver.clearCache()
                }

                override fun onLost(network: android.net.Network) {
                    Log.i("PinkVpnService", "Network lost: $network")
                    RobustResolver.clearCache()
                }

                override fun onCapabilitiesChanged(network: android.net.Network, capabilities: android.net.NetworkCapabilities) {
                    if (capabilities.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                        Log.i("PinkVpnService", "Network validated: $network")
                    }
                }
            }
            connectivityManager?.registerDefaultNetworkCallback(networkCallback!!)
        } catch (e: Exception) {
            Log.e("PinkVpnService", "Failed to register network monitor", e)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
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
            } catch (e: Exception) {
                Log.w("PinkVpnService", "Failed to add IPv6 route", e)
            }

            // Exclude or include packages
            if (isExcludeMode) {
                builder.addDisallowedApplication(packageName)
                selectedPackages.forEach { pkg ->
                    try { builder.addDisallowedApplication(pkg) } catch (e: Exception) { android.util.Log.v("PinkVpn", "Ignored app config: ${e.message}") }
                }
            } else {
                selectedPackages.filter { it != packageName }.forEach { pkg ->
                    try { builder.addAllowedApplication(pkg) } catch (e: Exception) { android.util.Log.v("PinkVpn", "Ignored app config: ${e.message}") }
                }
            }

            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                Log.e("PinkVpnService", "Failed to establish VPN interface")
                stopVpn()
                return
            }

            proxyServer?.start() // Ensure proxy is running
            
            // Start tun2socks
            startTun2Socks(vpnInterface!!, PROXY_PORT)
            
            showNotification()
            _isRunning.value = true
            VpnRuntimeState.updateState(VpnLifecycleState.RUNNING)
        } catch (e: Exception) {
            Log.e("PinkVpnService", "Error starting VPN", e)
            stopVpn()
        }
    }
    
    private fun startTun2Socks(vpnInterface: ParcelFileDescriptor, proxyPort: Int) {
        try {
            engine.Engine.touch()
            val key = engine.Key()
            key.setProxy("socks5://127.0.0.1:$proxyPort")
            key.setDevice("fd://${vpnInterface.fd}")
            key.setLogLevel("info")
            engine.Engine.insert(key)
            kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
                try {
                    engine.Engine.start()
                    Log.i("PinkVpnService", "tun2socks stopped naturally")
                } catch (e: Exception) {
                    Log.e("PinkVpnService", "tun2socks error", e)
                }
            }
            Log.i("PinkVpnService", "tun2socks started on fd ${vpnInterface.fd}")
        } catch (e: Exception) {
            Log.e("PinkVpnService", "Failed to start tun2socks", e)
        }
    }

    private fun stopTun2Socks() {
        try {
            engine.Engine.stop()
            Log.i("PinkVpnService", "tun2socks stopped")
        } catch (e: Exception) {
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
            .setContentTitle("PinkProxy is Active")
            .setContentText("Routing traffic via tun2socks")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pendingIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "STOP", stopPendingIntent)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(1, notification, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(1, notification)
        }
    }

    private fun stopVpn() {
        _isRunning.value = false
        VpnRuntimeState.updateState(VpnLifecycleState.IDLE)
        stopTun2Socks()
        proxyServer?.stop()
        
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
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

    override fun onRevoke() {
        super.onRevoke()
        stopVpn()
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
        try {
            networkCallback?.let { connectivityManager?.unregisterNetworkCallback(it) }
        } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        serviceScope.cancel()
        instance = null
        BypassConfig.activeVpnService = null
    }
}
