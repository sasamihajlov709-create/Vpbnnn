package com.example

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ProxyInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.PowerManager
import android.provider.Settings
import android.net.Uri
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer

class PinkVpnService : VpnService() {

    companion object {
        private val _isRunning = MutableStateFlow(false)
        val isRunning: StateFlow<Boolean> = _isRunning.asStateFlow()
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var proxyServer: PinkProxyServer? = null
    private val PROXY_PORT = 8080
    
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var connectivityManager: ConnectivityManager? = null
    
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            super.onAvailable(network)
            ProxyStats.logRecovery("Network Changed: Re-checking connectivity")
            ServiceChecker.triggerCheck()
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action == "STOP") {
            stopVpn()
            _isRunning.value = false
            return START_NOT_STICKY
        }
        if (action == "RESTART") {
            serviceScope.launch {
                ProxyStats.logRecovery("Manual Optimization Triggered")
                proxyServer?.stop()
                ProxyStats.reset(clearLog = false)
                BypassConfig.rotateStrategy()
                delay(1000)
                proxyServer = PinkProxyServer(this@PinkVpnService, PROXY_PORT)
                proxyServer?.start()
                ServiceChecker.triggerCheck()
                ProxyStats.logRecovery("Core System Re-Started")
            }
            return START_STICKY
        }
        
        if (intent != null) {
            _isRunning.value = true
            startVpn()
            checkBatteryOptimization()
        }
        return START_STICKY
    }

    private fun checkBatteryOptimization() {
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        if (!pm.isIgnoringBatteryOptimizations(packageName)) {
            ProxyStats.logRecovery("WARNING: Battery optimization is ACTIVE. App may be killed.")
            // We can't easily show a dialog from a service, but we can send a broadcast or just rely on the UI
            // to check this. MainActivity already has context.
        }
    }

    private fun startVpn() {
        if (vpnInterface != null) return

        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        connectivityManager?.registerNetworkCallback(
            NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build(),
            networkCallback
        )

        createNotificationChannel()
        val notificationIntent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, notificationIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification = NotificationCompat.Builder(this, "pink_proxy_channel")
            .setContentTitle("PinkProxy is Active")
            .setContentText("Your traffic is being routed securely.")
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(1, notification)
        }

        // Sanity check: ensure we are prepared
        if (prepare(this) != null) {
            Log.e("PinkVpnService", "VPN not prepared. Stopping.")
            stopSelf()
            return
        }

        try {
            ServiceChecker.proxyPort = PROXY_PORT
            // Start local HTTP proxy server for DPI Bypass
            proxyServer = PinkProxyServer(this, PROXY_PORT)
            proxyServer?.start()

            val builder = Builder()
                .addAddress("10.0.0.2", 24)
                .addDnsServer("8.8.8.8")
                .addDnsServer("1.1.1.1")
                // We rely on setHttpProxy for most traffic. 
                // Global routing without packet processing causes connectivity loss.
                .setSession("PinkProxy")
                .setBlocking(false)
                .setMtu(1400)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                // Route traffic through our local proxy
                builder.setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", PROXY_PORT))
            }
            
            builder.addDisallowedApplication(packageName)
            builder.addRoute("10.0.0.0", 8) // Internal route to keep VPN active

            vpnInterface = builder.establish()
            
            // Minimal TUN reader to prevent buffer overflow
            serviceScope.launch(Dispatchers.IO) {
                val fd = vpnInterface?.fileDescriptor ?: return@launch
                val inputStream = FileInputStream(fd)
                val buffer = ByteBuffer.allocate(16384)
                val bytes = ByteArray(16384)
                try {
                    while (isRunning.value) {
                        val read = inputStream.read(bytes)
                        if (read <= 0) {
                            delay(50) // Reduce CPU usage when idle
                            continue
                        }
                        // We don't process packets here as we use HTTP Proxy for bypass.
                        // This loop just keeps the TUN interface clean.
                    }
                } catch (e: Exception) {
                    Log.e("PinkVpnService", "TUN reader error", e)
                }
            }
            
            ServiceChecker.startChecking(serviceScope)
            
            // Watchdog and Notification Updater
            serviceScope.launch {
                combine(ProxyStats.speedBytesPerSecond, ServiceChecker.statuses) { speed, statuses ->
                    val onlineCount = statuses.count { it.isUp }
                    val totalCount = statuses.size
                    val speedStr = ProxyStats.formatBytes(speed) + "/s"
                    val youtubeStatus = if (statuses.any { it.name == "YouTube" && it.isUp }) "YT: OK" else "YT: DOWN"
                    Pair(speedStr, "$youtubeStatus | $onlineCount/$totalCount online")
                }.collect { (speed, services) ->
                    updateNotification(speed, services)
                }
            }

            serviceScope.launch {
                var lastLogTime = System.currentTimeMillis()
                var ytDownCount = 0
                var lastStatusMap = mutableMapOf<String, Boolean>()
                
                combine(
                    ServiceChecker.proxyHealth,
                    ServiceChecker.internetAvailable,
                    ProxyStats.errors,
                    ServiceChecker.statuses,
                    ServiceChecker.connectivityScore
                ) { isHealthy, isInternetUp, errors, statuses, score ->
                    val youtubeDown = statuses.find { it.name == "YouTube" }?.isUp == false
                    val streamDown = statuses.find { it.name == "YT Video Stream" }?.isUp == false
                    val telegramDown = statuses.find { it.name == "Telegram" }?.isUp == false
                    val allServicesUp = statuses.isNotEmpty() && statuses.all { it.isUp }
                    
                    // Success detection
                    statuses.forEach { status ->
                        if (status.isUp && lastStatusMap[status.name] == false) {
                            ProxyStats.logRecovery("Recovered: ${status.name}")
                            ProxyStats.recordSuccess(BypassConfig.strategy.value)
                        }
                        lastStatusMap[status.name] = status.isUp
                    }

                    if (allServicesUp && System.currentTimeMillis() - lastLogTime > 300000) {
                        ProxyStats.logRecovery("System Integrity: $score% Healthy")
                        ProxyStats.autoCleanup()
                        lastLogTime = System.currentTimeMillis()
                    }

                    val keyServicesDown = youtubeDown || telegramDown || streamDown
                    val controlServicesUp = statuses.filter { it.name.contains("Control") }.all { it.isUp }
                    
                    if ((youtubeDown || streamDown) && isInternetUp) ytDownCount++ else ytDownCount = 0
                    
                    // Specific block detected if key services are down but control services (VK/Rutube) are UP
                    val isSpecificBlock = keyServicesDown && controlServicesUp && statuses.isNotEmpty()
                    
                    // Force restart if YouTube/Stream is down for too long (30s = 3 checks)
                    val forceRestart = ytDownCount >= 3 || (score < 40 && statuses.isNotEmpty())
                    
                    val needsRestart = (!isHealthy || errors > 200 || isSpecificBlock || forceRestart)
                    val reason = when {
                        !isHealthy -> "Proxy Unresponsive"
                        errors > 200 -> "High Error Rate ($errors)"
                        isSpecificBlock -> "Targeted Block Detected (YT/TG/Stream)"
                        forceRestart -> if (score < 40) "Low Connectivity Index ($score%)" else "YouTube Throttled/Blocked (Persistent)"
                        else -> ""
                    }
                    Triple(needsRestart, isInternetUp, reason)
                }.collect { (needsRestart, isInternetUp, reason) ->
                    if (needsRestart && isInternetUp && isRunning.value) {
                        ProxyStats.logRecovery("Self-Healing: $reason")
                        
                        // Penalize current strategy if it's a specific block
                        if (reason.contains("Block") || reason.contains("Throttled")) {
                            BypassConfig.recordFailure(BypassConfig.strategy.value)
                            BypassConfig.rotateStrategy()
                        }
                        
                        Log.w("PinkVpnService", "Watchdog: Automated recovery triggered ($reason). Restarting core...")
                        proxyServer?.stop()
                        ProxyStats.reset(clearLog = false)
                        delay(1000)
                        proxyServer = PinkProxyServer(this@PinkVpnService, PROXY_PORT)
                        proxyServer?.start()
                        
                        // Force a service check after restart
                        ServiceChecker.triggerCheck()
                        
                        ProxyStats.logRecovery("Core System Re-Optimized")
                    }
                }
            }

        } catch (e: Exception) {
            Log.e("PinkVpnService", "Error starting VPN", e)
            stopVpn()
        }
    }

    private fun updateNotification(speed: String, servicesInfo: String) {
        val notificationIntent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, notificationIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification = NotificationCompat.Builder(this, "pink_proxy_channel")
            .setContentTitle("PinkProxy: $speed")
            .setContentText(servicesInfo)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(1, notification)
        }
    }

    private fun stopVpn() {
        _isRunning.value = false
        try {
            connectivityManager?.unregisterNetworkCallback(networkCallback)
        } catch (e: Exception) {}
        ServiceChecker.stopChecking()
        proxyServer?.stop()
        proxyServer = null
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e("PinkVpnService", "Error closing VPN interface", e)
        }
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        super.onRevoke()
        stopVpn()
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
        serviceScope.cancel()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                "pink_proxy_channel",
                "PinkProxy Service",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }
    }
}
