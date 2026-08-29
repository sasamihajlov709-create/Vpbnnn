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

    val serviceScope = CoroutineScope(ProxyDispatcher.io + SupervisorJob() + ProxyDispatcher.globalHandler)
    private var sessionScope: CoroutineScope? = null


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
    private var activeNetworkProfile: NetworkProfile = NetworkProfile.UNKNOWN

    override fun onCreate() {
        super.onCreate()
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
        notificationController.showNotification()
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
            serviceScope.launch {
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
        Log.i("PinkVpnService", "Starting VPN internal sequence...")

        val session = VpnSessionManager.startSession(this@PinkVpnService)

        // Try to initialize Cronet (background)
        session.controlPlaneScope.launch {
            com.aistudio.pinkproxy.fresh.cronet.CronetEngineProvider.initialize(this@PinkVpnService)
        }

        try {
            ProxyStats.reset(false)
            ServiceChecker.proxyPort = PROXY_PORT
            activeNetworkProfile = NetworkProfileManager.currentProfile.value

            // 1. Initialize DNS
            VpnRuntimeState.updateState(VpnLifecycleState.STARTING, "Initializing DNS resolver...")
            RobustResolver.initialize(session.dnsScope)
            RobustResolver.startDnsOptimizer(session.dnsScope, this@PinkVpnService)

            // 2. Start Proxy Server
            VpnRuntimeState.updateState(VpnLifecycleState.STARTING, "Starting SOCKS5/HTTP core proxy...")
            proxyServer?.stop()
            proxyServer = null
            delay(150)
            val newProxy = PinkProxyServer(this@PinkVpnService, PROXY_PORT, proxySecret)
            newProxy.start()
            proxyServer = newProxy

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
            VpnRuntimeState.updateState(VpnLifecycleState.STARTING, "Configuring TUN interface...")
            val pfd = try {
                vpnTunnelManager?.establish(
                    sessionName = "PinkProxy VPN",
                    mtu = BypassConfig.getMtuForTransport(TransportType.TCP),
                    addressV4 = "10.0.0.2",
                    prefixV4 = 24,
                    dnsServers = dnsServers,
                    includeIpv6 = BypassConfig.includeIpv6,
                    isExcludeMode = isExcludeMode,
                    selectedPackages = selectedPackages,
                    appPackageName = packageName,
                    allowBypass = !BypassConfig.isKillSwitchEnabled.value,
                    isBlocking = BypassConfig.isKillSwitchEnabled.value
                ) ?: throw java.io.IOException("Failed to establish tunnel interface")
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
                    isExcludeMode = isExcludeMode,
                    selectedPackages = selectedPackages,
                    appPackageName = packageName,
                    allowBypass = !BypassConfig.isKillSwitchEnabled.value,
                    isBlocking = BypassConfig.isKillSwitchEnabled.value
                ) ?: throw e
            }

            AutoTtlProber.startProbing(session.learningScope, this@PinkVpnService)

            try {
                wakeLock?.acquire(24 * 60 * 60 * 1000L)
            } catch (e: Exception) {
                Log.e("PinkVpnService", "Failed to acquire wakeLock: ${e.message}")
            }

            // 5. Start tun2socks engine (transactional - only set _isRunning after verified launch)
            VpnRuntimeState.updateState(VpnLifecycleState.STARTING, "Binding transport engine to TUN...")
            startTun2Socks(pfd, PROXY_PORT)

            // 6. Execute End-to-End Transport Probe before marking RUNNING
            VpnRuntimeState.updateState(VpnLifecycleState.PROBING, "Verifying end-to-end transport routing...")
            val probeSuccess = performE2EHealthProbe(PROXY_PORT, proxySecret)
            if (!probeSuccess) {
                Log.w("PinkVpnService", "Local proxy health probe failed! Triggering restart recovery")
                VpnRuntimeState.updateState(VpnLifecycleState.DEGRADED, "Local proxy probe failed, attempting recovery...")
                restartProxyServer()
                val retrySuccess = performE2EHealthProbe(PROXY_PORT, proxySecret)
                if (!retrySuccess) {
                    throw java.io.IOException("Critical: Core proxy failed health verification on port $PROXY_PORT")
                }
            }

            _isRunning.value = true

            // 7. Now that proxy & tun2socks are fully running, start health checkers & monitors
            RuntimeCoordinator.initialize(this@PinkVpnService)
            RecoveryStateMachine.start(session.recoveryScope)
            ServiceChecker.startChecking(session.controlPlaneScope, this@PinkVpnService)
            healthMonitor?.start(session.controlPlaneScope)

            startSessionWarmup()

            VpnRuntimeState.updateState(VpnLifecycleState.RUNNING)
            VpnRuntimeState.clearError()
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            Log.e("PinkVpnService", "Error starting VPN", e)
            _isRunning.value = false
            VpnRuntimeState.updateState(VpnLifecycleState.FAILED, "Critical startup error: ${e.localizedMessage}")
            stopVpnInternal()
        }
    }

    private suspend fun performE2EHealthProbe(proxyPort: Int, secret: String): Boolean = withContext(Dispatchers.IO) {
        try {
            // Verify local proxy listener accepts and responds with strict authentication
            java.net.Socket().use { probeSocket ->
                probeSocket.soTimeout = 1200
                probeSocket.connect(java.net.InetSocketAddress("127.0.0.1", proxyPort), 1200)
                
                val out = probeSocket.getOutputStream()
                val input = probeSocket.getInputStream()
                
                // Send SOCKS5 method negotiation: [VER=5, NMETHODS=1, METHOD=2 (USER/PASS)]
                out.write(byteArrayOf(0x05, 0x01, 0x02))
                out.flush()
                
                val methodResp = ByteArray(2)
                val readMethod = input.read(methodResp)
                if (readMethod < 2 || methodResp[0] != 0x05.toByte() || methodResp[1] != 0x02.toByte()) {
                    return@withContext false
                }
                
                // Send subnegotiation username/password: [VER=1, ULEN, USER, PLEN, PASS]
                val secBytes = secret.toByteArray(java.nio.charset.StandardCharsets.UTF_8)
                val authReq = ByteArray(3 + secBytes.size * 2)
                authReq[0] = 0x01
                authReq[1] = secBytes.size.toByte()
                System.arraycopy(secBytes, 0, authReq, 2, secBytes.size)
                authReq[2 + secBytes.size] = secBytes.size.toByte()
                System.arraycopy(secBytes, 0, authReq, 3 + secBytes.size, secBytes.size)
                
                out.write(authReq)
                out.flush()
                
                val authResp = ByteArray(2)
                val readAuth = input.read(authResp)
                readAuth >= 2 && authResp[0] == 0x01.toByte() && authResp[1] == 0x00.toByte()
            }
        } catch (e: Exception) {
            Log.w("PinkVpnService", "E2E probe socket verification failed: ${e.message}")
            false
        }
    }

    private fun startSessionWarmup() {
        VpnSessionManager.currentSession?.controlPlaneScope?.launch {
            delay(5000)
            ServiceChecker.runActiveProbing(this@PinkVpnService)
        }
    }

    private fun extractIpsFromDnsUrl(url: String): List<String> {
        val ipRegex = Regex("""\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b""")
        return ipRegex.findAll(url).map { it.value }.toList()
    }

    private suspend fun startTun2Socks(vpnInterface: ParcelFileDescriptor, proxyPort: Int) {
        var dupFd: ParcelFileDescriptor? = null
        var rawFd = -1
        try {
            engine.Engine.touch()
            val key = engine.Key()
            key.setProxy("socks5://$proxySecret:$proxySecret@127.0.0.1:$proxyPort")
            dupFd = vpnInterface.dup()
            rawFd = dupFd.detachFd()
            try { vpnInterface.close() } catch (ignored: Exception) {} // Close original to prevent FD leak
            key.setDevice("fd://$rawFd")
            key.setLogLevel("error")
            engine.Engine.insert(key)
            
            val startAck = CompletableDeferred<Unit>()
            serviceScope.launch {
                try {
                    // Launch native engine start
                    val startJob = launch(Dispatchers.IO) {
                        try {
                            engine.Engine.start()
                            Log.i("PinkVpnService", "tun2socks stopped naturally")
                        } catch (e: Exception) {
                            if (!startAck.isCompleted) {
                                startAck.completeExceptionally(e)
                            } else {
                                Log.e("PinkVpnService", "tun2socks run-time error", e)
                                VpnRuntimeState.updateState(VpnLifecycleState.ERROR, "Transport engine error: ${e.localizedMessage}")
                                recoveryCoordinator.triggerRestart()
                            }
                        }
                    }

                    // A brief yield and check that Engine didn't immediately crash/fail on invalid FD/proxy
                    delay(80)
                    if (startJob.isActive && !startAck.isCompleted) {
                        startAck.complete(Unit)
                    }
                } catch (e: CancellationException) {
                    if (!startAck.isCompleted) startAck.completeExceptionally(e)
                    throw e
                } catch (e: Exception) {
                    if (!startAck.isCompleted) {
                        startAck.completeExceptionally(e)
                    } else {
                        Log.e("PinkVpnService", "tun2socks supervisor error", e)
                        VpnRuntimeState.updateState(VpnLifecycleState.ERROR, "Transport engine error: ${e.localizedMessage}")
                        recoveryCoordinator.triggerRestart()
                    }
                }
            }

            // Wait up to 1500ms to guarantee coroutine started and engine initialized
            withTimeout(1500L) {
                startAck.await()
            }
            Log.i("PinkVpnService", "tun2socks started and verified on fd $rawFd")
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e("PinkVpnService", "Failed to start tun2socks", e)
            if (rawFd >= 0) {
                try {
                    ParcelFileDescriptor.adoptFd(rawFd).close()
                } catch (closeEx: Exception) {
                    Log.v("PinkVpnService", "FD adoption close error: ${closeEx.message}")
                }
            }
            try {
                dupFd?.close()
            } catch (_: Exception) {}
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
            RobustResolver.stopBackgroundProber()
            CensorshipExpert.stop()
            PrefetchManager.stop()
            AutoTtlProber.stopProbing()
            DnsProtocols.clearPool()
            UdpTransportHandler.clearBuffers()
            RecoveryStateMachine.stop()
            RuntimeCoordinator.shutdown(this@PinkVpnService)
            DeviceMonitor.stopDeviceMonitoring(this@PinkVpnService)

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
                serviceScope.cancel()
        ProxyDispatcher.cancelAllBackgroundJobs()
                BypassConfig.activeVpnService = null
                ProxyDispatcher.context = null
            }
        )
    }
}
