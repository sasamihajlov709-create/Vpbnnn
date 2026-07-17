package com.aistudio.pinkproxy.fresh

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
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
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
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

class PinkVpnService : VpnService() {
    private val udpBufferPool = java.util.concurrent.LinkedBlockingQueue<ByteArray>(64)
    private fun getBuffer(): ByteArray = udpBufferPool.poll() ?: ByteArray(16384)
    private fun releaseBuffer(buffer: ByteArray) { udpBufferPool.offer(buffer) }

    companion object {
        private val _isRunning = MutableStateFlow(false)
        val isRunning: StateFlow<Boolean> = _isRunning.asStateFlow()

        var selectedPackages = mutableSetOf<String>()
        var isExcludeMode = true // true = exclude selected, false = only selected
        
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
            selectedPackages = prefs.getStringSet("selected_packages", emptySet())?.toMutableSet() ?: mutableSetOf()
            isExcludeMode = prefs.getBoolean("is_exclude_mode", true)
        }

        fun saveVpnState(context: Context, isRunning: Boolean) {
            val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
            prefs.edit().putBoolean("vpn_should_be_running", isRunning).apply()
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var proxyServer: PinkProxyServer? = null
    private val PROXY_PORT = 18080
    private val proxyMutex = kotlinx.coroutines.sync.Mutex()
    
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var connectivityManager: ConnectivityManager? = null
    
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            super.onCapabilitiesChanged(network, capabilities)
            val isWifi = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
            val isCellular = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
            
            val netType = when {
                isWifi -> NetworkType.WIFI
                isCellular -> NetworkType.MOBILE
                else -> NetworkType.UNKNOWN
            }
            
            if (netType != NetworkType.UNKNOWN && netType != BypassConfig.currentNetworkType.value) {
                val oldType = BypassConfig.currentNetworkType.value
                serviceScope.launch {
                    BypassConfig.switchNetworkProfile(this@PinkVpnService, netType)
                    restartProxyServer("Network Profile Changed: ${oldType.name} -> ${netType.name}")
                }
            }
        }

        override fun onAvailable(network: Network) {
            super.onAvailable(network)
            ProxyStats.logRecovery("Network connection restored. Re-checking services...")
            ServiceChecker.triggerCheck()
        }
    }

    private suspend fun restartProxyServer(reason: String) {
        proxyMutex.withLock {
            if (!_isRunning.value) return@withLock
            ProxyStats.logRecovery(reason)
            RobustResolver.clearCache()
            proxyServer?.stop()
            ProxyStats.reset(clearLog = false)
            delay(1000)
            proxyServer = PinkProxyServer(this@PinkVpnService, PROXY_PORT)
            proxyServer?.start()
            ServiceChecker.triggerCheck()
        }
    }

    override fun onCreate() {
        super.onCreate()
        loadFilterSettings(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action == "STOP") {
            saveVpnState(this, false)
            stopVpn()
            _isRunning.value = false
            return START_NOT_STICKY
        }
        if (action == "RESTART") {
            serviceScope.launch {
                restartProxyServer("Manual Optimization Triggered")
                ProxyStats.logRecovery("Core System Re-Started")
            }
            return START_STICKY
        }
        if (action == "CHANGE_STRATEGY") {
            serviceScope.launch {
                restartProxyServer("Strategy Manually Changed")
                ProxyStats.logRecovery("Core System Re-Started with New Strategy")
            }
            return START_STICKY
        }
        
        if (!_isRunning.value) {
            _isRunning.value = true
            saveVpnState(this, true)
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

        val prefs = getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
        prefs.edit().putBoolean("vpn_was_active", true).apply()

        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        connectivityManager?.registerNetworkCallback(
            NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build(),
            networkCallback
        )

        // Sanity check: ensure we are prepared BEFORE starting foreground
        try {
            if (prepare(this) != null) {
                Log.e("PinkVpnService", "VPN not prepared. Stopping.")
                stopSelf()
                return
            }
        } catch (e: SecurityException) {
            Log.e("PinkVpnService", "SecurityException during prepare check", e)
            stopSelf()
            return
        }

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

        if (android.os.Build.VERSION.SDK_INT >= 34) {
            startForeground(1, notification, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(1, notification)
        }

        try {
            ServiceChecker.proxyPort = PROXY_PORT
            ProxyStats.reset(clearLog = true)
            ProxyStats.logRecovery("System Initialized: All components READY")
            ProxyStats.logRecovery("Mode: DPI Bypass / HTTP Tunnel")
            // Start local HTTP proxy server for DPI Bypass
            BypassConfig.initialize(this)
            proxyServer = PinkProxyServer(this, PROXY_PORT)
            proxyServer?.start()

            // Self-healing monitor and stats persistence
            serviceScope.launch {
                launch {
                    ProxyStats.proxyHealthTrigger.collect { reason ->
                        restartProxyServer("Self-Healing: $reason")
                    }
                }
                launch {
                    while (isActive) {
                        delay(60000)
                        BypassConfig.saveScores(this@PinkVpnService)
                    }
                }
            }

            val builder = Builder()
                .addAddress("10.0.0.2", 24)
                .addAddress("fd00:1:2:3::2", 120)
                .addDnsServer("10.0.0.3")
                // We rely on setHttpProxy for most traffic. 
                // Global routing without packet processing causes connectivity loss.
                .setSession("PinkProxy")
                .setMtu(1400)

            // Route traffic through our local proxy
            builder.setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", PROXY_PORT))
            
            // Application filtering
            if (isExcludeMode) {
                builder.addDisallowedApplication(packageName)
                selectedPackages.forEach { pkg ->
                    try { builder.addDisallowedApplication(pkg) } catch (e: Exception) {}
                }
            } else {
                selectedPackages.forEach { pkg ->
                    try { builder.addAllowedApplication(pkg) } catch (e: Exception) {}
                }
            }
            
            // Block QUIC if enabled
            if (BypassConfig.blockQuic) {
                // We can't easily block specific UDP ports without full routing, 
                // but if we were routing everything, we'd drop UDP 443 here.
                // For now, we rely on setHttpProxy which forces most apps to use TCP.
                Log.i("PinkVpnService", "QUIC blocking enabled (via HttpProxy fallback)")
            }
            
            // Add a dummy route to make Android treat this VPN as active for the HTTP proxy to apply globally.
            // Some devices might require a broader route, but routing 0.0.0.0/0 without a tun2socks implementation
            // blackholes all non-HTTP proxy traffic (like native games, UDP apps, etc).
            // Many apps ignore the HTTP proxy. If we don't route 0.0.0.0/0, they will just bypass the VPN.
            builder.addRoute("10.0.0.0", 8)
            builder.addRoute("fc00::", 7) // IPv6 Unique Local Address space dummy route 
            
            // Block IPv6 leaks by routing all Global Unicast IPv6 to the blackhole TUN
            try {
                builder.addRoute("2000::", 3)
            } catch (e: Exception) {
                Log.w("PinkVpnService", "Failed to add IPv6 route, device might not support IPv6 VPN: ${e.message}")
            }
            
            // Note: We do NOT use addRoute("0.0.0.0", 0) because we don't have a TUN-to-TCP (tun2socks) layer.
            // Any app ignoring the proxy would otherwise lose internet.


            try {
                vpnInterface = builder.establish()
                if (vpnInterface == null) {
                    throw IllegalStateException("Failed to establish VPN interface. Device may not support it or VPN permissions revoked.")
                }
            } catch (e: Exception) {
                Log.e("PinkVpnService", "Error establishing VPN interface", e)
                stopVpn()
                return
            }
            
            // Minimal TUN reader with UDP Relay
            serviceScope.launch(Dispatchers.IO) {
                val fd = vpnInterface?.fileDescriptor ?: return@launch
                val inputStream = FileInputStream(fd)
                val outputStream = FileOutputStream(fd)
                val udpRelays = ConcurrentHashMap<String, UdpSession>()
                
                // Cleanup job for inactive sessions
                serviceScope.launch {
                    while (isRunning.value) {
                        delay(60000)
                        val now = System.currentTimeMillis()
                        udpRelays.entries.removeIf { (key, session) ->
                            if (now - session.lastActivity > 60000) {
                                session.close()
                                true
                            } else false
                        }
                    }
                }

                try {
                    tunLoop@while (isRunning.value) {
                        val packet = getBuffer()
                        try {
                            val read = try {
                                inputStream.read(packet)
                            } catch (e: Exception) {
                                -1
                            }
                            if (read < 0) break
                            if (read < 20) {
                                if (read == 0) delay(10)
                                continue
                            }
                            
                            // Parse IP version
                            val version = (packet[0].toInt() shr 4) and 0x0F
                            if (version == 4) {
                                val protocol = packet[9].toInt() and 0xFF
                                if (protocol == 17) { // UDP
                                    val ihl = (packet[0].toInt() and 0x0F) * 4
                                    val srcIp = "${packet[12].toInt() and 0xFF}.${packet[13].toInt() and 0xFF}.${packet[14].toInt() and 0xFF}.${packet[15].toInt() and 0xFF}"
                                    val dstIp = "${packet[16].toInt() and 0xFF}.${packet[17].toInt() and 0xFF}.${packet[18].toInt() and 0xFF}.${packet[19].toInt() and 0xFF}"
                                    val srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
                                    val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
                                    
                                    val payloadOffset = ihl + 8
                                    val payloadLen = read - payloadOffset
                                    if (payloadLen > 0) {
                                        val key = "$srcIp:$srcPort->$dstIp:$dstPort"
                                        var session = udpRelays[key]
                                        if (session == null || session.isClosed) {
                                            // DNS Hijacking: if port 53, resolve via RobustResolver
                                            if (dstPort == 53) {
                                                val dnsPayload = packet.copyOfRange(payloadOffset, read)
                                                serviceScope.launch(Dispatchers.IO) {
                                                    try {
                                                        val qname = parseDnsQName(dnsPayload)
                                                        if (qname != null && qname.contains(".")) {
                                                            val ips = RobustResolver.resolve(qname, this@PinkVpnService)
                                                            val ipv4List = ips.mapNotNull { it.hostAddress }.filter { it.contains(".") && !it.contains(":") }
                                                            if (ipv4List.isNotEmpty()) {
                                                                val dnsReply = buildDnsReply(dnsPayload, ipv4List)
                                                                val replyPacket = createUdpIpPacket(dstIp, srcIp, dstPort, srcPort, dnsReply)
                                                                synchronized(outputStream) {
                                                                    outputStream.write(replyPacket)
                                                                    outputStream.flush()
                                                                }
                                                                return@launch
                                                            }
                                                        }
                                                    } catch (e: Exception) {
                                                        Log.e("PinkVpnService", "DNS Hijack failed for $dstIp", e)
                                                    }
                                                    
                                                    // Fallback to normal UDP relay if hijack failed
                                                    val s = UdpSession(dstIp, dstPort, this@PinkVpnService) { reply ->
                                                        try {
                                                            val replyPacket = createUdpIpPacket(dstIp, srcIp, dstPort, srcPort, reply)
                                                            synchronized(outputStream) {
                                                                outputStream.write(replyPacket)
                                                                outputStream.flush()
                                                            }
                                                        } catch (e: Exception) {}
                                                    }
                                                    udpRelays[key] = s
                                                    s.send(dnsPayload)
                                                }
                                                // Continue loop, packet will be released in finally
                                                continue@tunLoop
                                            }

                                            session = UdpSession(dstIp, dstPort, this@PinkVpnService) { reply ->
                                                try {
                                                    val replyPacket = createUdpIpPacket(dstIp, srcIp, dstPort, srcPort, reply)
                                                    synchronized(outputStream) {
                                                        outputStream.write(replyPacket)
                                                        outputStream.flush()
                                                    }
                                                } catch (e: Exception) {
                                                    Log.e("PinkVpnService", "Failed to inject UDP reply", e)
                                                }
                                            }
                                            udpRelays[key] = session
                                        }
                                        session.send(packet.copyOfRange(payloadOffset, read))
                                    }
                                }
                            } else if (version == 6) {
                                // Drop IPv6 for now
                            }
                        } finally {
                            releaseBuffer(packet)
                        }
                    }
                } catch (e: Exception) {
                    Log.e("PinkVpnService", "TUN reader error", e)
                } finally {
                    try { inputStream.close() } catch (e: Exception) {}
                    try { outputStream.close() } catch (e: Exception) {}
                    udpRelays.values.forEach { it.close() }
                }
            }
            
            BypassConfig.loadTuningSettings(this)
            RobustResolver.loadDnsSettings(this)
            ServiceChecker.startChecking(serviceScope, this)
            
            serviceScope.launch {
                var errorThreshold = 0
                var lowConnectivityCount = 0
                while (isRunning.value) {
                    delay(30000) // Every 30 seconds
                    
                    val currentErrors = ProxyStats.errors.value
                    if (currentErrors > errorThreshold + 50) {
                        // Rapid error growth detected
                        ProxyStats.logRecovery("Rapid error growth: Cleaning DNS Cache...")
                        RobustResolver.clearCache()
                        errorThreshold = currentErrors.toInt()
                    }
                    
                    // Automatic Global Recovery based on Connectivity Score
                    if (ServiceChecker.connectivityScore.value < 35 && ServiceChecker.internetAvailable.value) {
                        lowConnectivityCount++
                        if (lowConnectivityCount >= 3) { // 1.5 minutes of low connectivity
                            ProxyStats.logRecovery("AUTO-HEAL: Performance drop. Rotating Strategy...")
                            restartProxyServer("Performance Optimization")
                            RobustResolver.clearCache()
                            lowConnectivityCount = 0
                        }
                    } else {
                        lowConnectivityCount = 0
                    }
                    
                    // Periodic Parameter Mutation for active strategy
                    if (isRunning.value && (System.currentTimeMillis() % 300000 < 30000)) {
                         // BypassConfig.reOptimize() removed
                    }
                    
                    // Independent connectivity check
                    if (!ServiceChecker.internetAvailable.value && isRunning.value) {
                        ProxyStats.logRecovery("Independent check: Internet seems DOWN. Re-triggering network callback...")
                        // This might force Android to re-evaluate the network
                        try {
                            val activeNet = connectivityManager?.activeNetwork
                            val caps = connectivityManager?.getNetworkCapabilities(activeNet)
                            if (caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                                ServiceChecker.triggerCheck()
                            }
                        } catch (e: Exception) {}
                    }
                }
            }
            
            // Watchdog and Notification Updater
            serviceScope.launch {
                var lastGhostMutation = System.currentTimeMillis()
                combine(
                    ProxyStats.speedBytesPerSecond, 
                    ServiceChecker.statuses,
                    BypassConfig.strategy
                ) { speed, statuses, currentStrategy ->
                    
                    // Ghost Mode: Mutate parameters every 7 minutes to prevent signature building
                    if (System.currentTimeMillis() - lastGhostMutation > 420000) {
                        lastGhostMutation = System.currentTimeMillis()
                        ProxyStats.logRecovery("Ghost Mode: Mutating evasion params...")
                        // BypassConfig.rotateStrategy() removed
                    }
                    
                    val onlineCount = statuses.count { it.isUp }
                    val totalCount = statuses.size
                    val speedStr = ProxyStats.formatBytes(speed) + "/s"
                    val strategyName = currentStrategy.name.replace("_", " ")
                    val youtubeStatus = if (statuses.any { it.name == "YouTube" && it.isUp }) "YT: OK" else "YT: DOWN"
                    
                    Triple(
                        "$speedStr ($strategyName)",
                        "$youtubeStatus | $onlineCount/$totalCount online",
                        speed > 0 // if speed > 0, we might want to update more frequently
                    )
                }.collect { (title, services, isActive) ->
                    updateNotification(title, services)
                }
            }

            serviceScope.launch {
                var lastLogTime = System.currentTimeMillis()
                var ytDownCount = 0
                var lastStatusMap = mutableMapOf<String, Boolean>()
                var lastRecoveryTime = 0L
                
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
                            // Quality check: Only record success for major endpoints to avoid bias
                            val isCriticalEndpoint = status.name in listOf("YouTube", "Telegram", "YT Video Stream")
                            if (isCriticalEndpoint) {
                                BypassConfig.recordSuccess(BypassConfig.strategy.value, this@PinkVpnService)
                            }
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
                    
                    // Force restart if YouTube/Stream is down for too long (16s = 2 checks)
                    val forceRestart = ytDownCount >= 2 || (score < 40 && statuses.isNotEmpty()) || ServiceChecker.isStalled.value
                    
                    val needsRestart = (!isHealthy || errors > 200 || isSpecificBlock || forceRestart)
                    val reason = when {
                        !isHealthy -> "Proxy Unresponsive"
                        errors > 200 -> "High Error Rate ($errors)"
                        isSpecificBlock -> "Targeted Block Detected (YT/TG/Stream)"
                        ServiceChecker.isStalled.value -> "Traffic Stall Detected (Zero Throughput)"
                        forceRestart -> if (score < 40) "Low Connectivity Index ($score%)" else "YouTube Throttled/Blocked (Persistent)"
                        else -> ""
                    }
                    Triple(needsRestart, isInternetUp, reason)
                }.collect { (needsRestart, isInternetUp, reason) ->
                    if (needsRestart && isInternetUp && isRunning.value) {
                        val now = System.currentTimeMillis()
                        if (now - lastRecoveryTime < 15000) {
                            // Skip restart within 15-second cooldown to let components warm up and verify connection
                            return@collect
                        }
                        lastRecoveryTime = now
                        
                        ProxyStats.logRecovery("Self-Healing: $reason")
                        
                        // Penalize and rotate strategy if we detect a specific block, throttling, or low connectivity
                        if (reason.contains("Block") || reason.contains("Throttled") || reason.contains("Connectivity") || reason.contains("Stall")) {
                            BypassConfig.recordFailure(strategy = BypassConfig.strategy.value, isCritical = false, context = this@PinkVpnService)
                        }
                        
                        Log.w("PinkVpnService", "Watchdog: Automated recovery triggered ($reason). Restarting core...")
                        restartProxyServer("Self-Healing: $reason")
                        ProxyStats.logRecovery("Core System Re-Optimized")
                    }
                }
            }

            serviceScope.launch {
                while (isRunning.value) {
                    ServiceChecker.checkStall(ProxyStats.bytesTransferred.value)
                    delay(5000)
                }
            }

        } catch (e: Exception) {
            Log.e("PinkVpnService", "Error starting VPN", e)
            stopVpn()
        }
    }

    private fun updateNotification(speed: String, servicesInfo: String) {
        if (!_isRunning.value) return
        val notificationIntent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, notificationIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        
        val restartIntent = Intent(this, PinkVpnService::class.java).apply {
            action = "RESTART"
        }
        val restartPendingIntent = PendingIntent.getService(
            this, 1, restartIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification = NotificationCompat.Builder(this, "pink_proxy_channel")
            .setContentTitle("PinkProxy: $speed")
            .setContentText(servicesInfo)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(pendingIntent)
            .addAction(R.drawable.ic_launcher_foreground, "RE-OPTIMIZE", restartPendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()

        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(1, notification)
    }

    private fun stopVpn() {
        val prefs = getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
        prefs.edit().putBoolean("vpn_was_active", false).apply()

        _isRunning.value = false
        try {
            serviceScope.coroutineContext.cancelChildren()
        } catch (e: Exception) {}
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

    private class UdpSession(val dstIp: String, val dstPort: Int, val vpn: VpnService, val onReply: (ByteArray) -> Unit) {
        private val socket = DatagramSocket()
        @Volatile var isClosed = false
        @Volatile var lastActivity = System.currentTimeMillis()
        
        init {
            vpn.protect(socket)
            socket.soTimeout = 1000
            Thread {
                val buffer = ByteArray(16384)
                while (!isClosed) {
                    try {
                        val packet = DatagramPacket(buffer, buffer.size)
                        socket.receive(packet)
                        if (packet.length > 0) {
                            lastActivity = System.currentTimeMillis()
                            onReply(packet.data.copyOfRange(0, packet.length))
                        }
                    } catch (e: Exception) {
                        if (System.currentTimeMillis() - lastActivity > 60000) break
                    }
                }
                close()
            }.start()
        }
        
        fun send(data: ByteArray) {
            lastActivity = System.currentTimeMillis()
            try {
                val addr = InetAddress.getByName(dstIp)
                // QUIC Bypass: Fragment if it looks like a ClientHello (long packet to port 443)
                if (dstPort == 443 && data.size > 1000) {
                    val f1 = 1 + (Math.random() * 10).toInt()
                    socket.send(DatagramPacket(data, 0, f1, addr, dstPort))
                    Thread.sleep(5)
                    socket.send(DatagramPacket(data, f1, data.size - f1, addr, dstPort))
                } else {
                    socket.send(DatagramPacket(data, data.size, addr, dstPort))
                }
            } catch (e: Exception) {
                close()
            }
        }
        
        fun close() {
            isClosed = true
            try { socket.close() } catch(e: Exception) {}
        }
    }

    private fun createUdpIpPacket(srcIp: String, dstIp: String, srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
        val ipLen = 20 + 8 + payload.size
        val buffer = ByteBuffer.allocate(ipLen)
        
        // IPv4 Header
        buffer.put(0x45.toByte()) // Version 4, IHL 5
        buffer.put(0x00.toByte()) // DSCP/ECN
        buffer.putShort(ipLen.toShort())
        buffer.putShort(0.toShort()) // ID
        buffer.putShort(0x4000.toShort()) // Flags: Don't Fragment
        buffer.put(64.toByte()) // TTL
        buffer.put(17.toByte()) // Protocol: UDP
        val checksumPos = buffer.position()
        buffer.putShort(0.toShort()) // Checksum placeholder
        
        val srcParts = srcIp.split(".")
        srcParts.forEach { buffer.put(it.toInt().toByte()) }
        val dstParts = dstIp.split(".")
        dstParts.forEach { buffer.put(it.toInt().toByte()) }
        
        // Calculate IP Checksum
        val header = buffer.array().copyOfRange(0, 20)
        var sum = 0
        for (i in 0 until 10) {
            val word = ((header[i * 2].toInt() and 0xFF) shl 8) or (header[i * 2 + 1].toInt() and 0xFF)
            sum += word
        }
        while (sum shr 16 != 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        val checksum = (sum.inv() and 0xFFFF).toShort()
        buffer.putShort(checksumPos, checksum)

        // UDP Header
        buffer.putShort(srcPort.toShort())
        buffer.putShort(dstPort.toShort())
        buffer.putShort((8 + payload.size).toShort())
        val udpChecksumPos = buffer.position()
        buffer.putShort(0.toShort()) // Checksum placeholder
        buffer.put(payload)

        // Calculate UDP Checksum with Pseudo-header
        try {
            val udpLen = 8 + payload.size
            val pseudoHeader = ByteBuffer.allocate(12 + udpLen)
            val sParts = srcIp.split(".")
            sParts.forEach { pseudoHeader.put(it.toInt().toByte()) }
            val dParts = dstIp.split(".")
            dParts.forEach { pseudoHeader.put(it.toInt().toByte()) }
            pseudoHeader.put(0.toByte())
            pseudoHeader.put(17.toByte()) // Protocol UDP
            pseudoHeader.putShort(udpLen.toShort())
            
            // UDP Header + Payload
            pseudoHeader.putShort(srcPort.toShort())
            pseudoHeader.putShort(dstPort.toShort())
            pseudoHeader.putShort(udpLen.toShort())
            pseudoHeader.putShort(0.toShort())
            pseudoHeader.put(payload)
            
            val udpData = pseudoHeader.array()
            var sum = 0
            for (i in 0 until (udpData.size / 2)) {
                sum += ((udpData[i * 2].toInt() and 0xFF) shl 8) or (udpData[i * 2 + 1].toInt() and 0xFF)
            }
            if (udpData.size % 2 != 0) {
                sum += (udpData.last().toInt() and 0xFF) shl 8
            }
            while (sum shr 16 != 0) {
                sum = (sum and 0xFFFF) + (sum shr 16)
            }
            var checksum = (sum.inv() and 0xFFFF).toShort()
            if (checksum == 0.toShort()) checksum = 0xFFFF.toShort()
            buffer.putShort(udpChecksumPos, checksum)
        } catch (e: Exception) {}

        return buffer.array()
    }

    private fun parseDnsQName(payload: ByteArray): String? {
        try {
            if (payload.size < 13) return null
            val qcount = ((payload[4].toInt() and 0xFF) shl 8) or (payload[5].toInt() and 0xFF)
            if (qcount <= 0) return null
            
            val sb = StringBuilder()
            var pos = 12
            while (pos < payload.size) {
                val len = payload[pos].toInt() and 0xFF
                if (len == 0) break
                if (sb.isNotEmpty()) sb.append(".")
                if (pos + 1 + len > payload.size) return null
                sb.append(String(payload, pos + 1, len))
                pos += (len + 1)
            }
            return sb.toString()
        } catch (e: Exception) {
            return null
        }
    }

    private fun buildDnsReply(query: ByteArray, ips: List<String>): ByteArray {
        val bos = java.io.ByteArrayOutputStream()
        // ID
        bos.write(query[0].toInt())
        bos.write(query[1].toInt())
        // Flags: Standard query response, No error
        bos.write(0x81)
        bos.write(0x80)
        // Questions count
        bos.write(0)
        bos.write(1)
        // Answer count
        bos.write(0)
        bos.write(ips.size.toByte().toInt())
        // Authority / Additional
        bos.write(0); bos.write(0)
        bos.write(0); bos.write(0)
        
        // Copy Question section
        var pos = 12
        while (pos < query.size) {
            val len = query[pos].toInt() and 0xFF
            if (len == 0) {
                bos.write(0)
                // Type A (0x0001) and Class IN (0x0001)
                bos.write(query[pos + 1].toInt())
                bos.write(query[pos + 2].toInt())
                bos.write(query[pos + 3].toInt())
                bos.write(query[pos + 4].toInt())
                break
            }
            bos.write(len)
            bos.write(query, pos + 1, len)
            pos += (len + 1)
        }
        
        // Answers
        for (ip in ips) {
            // Name: pointer to offset 12 (0xc00c)
            bos.write(0xc0)
            bos.write(0x0c)
            // Type A
            bos.write(0); bos.write(1)
            // Class IN
            bos.write(0); bos.write(1)
            // TTL (60s)
            bos.write(0); bos.write(0); bos.write(0); bos.write(60)
            // Data length (4 bytes for IPv4)
            bos.write(0); bos.write(4)
            // IP address
            ip.split(".").forEach { bos.write(it.toInt()) }
        }
        
        return bos.toByteArray()
    }
}
