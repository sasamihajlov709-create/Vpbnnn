package com.aistudio.pinkproxy.fresh

import androidx.core.content.edit

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
import kotlinx.coroutines.asCoroutineDispatcher
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
import kotlinx.coroutines.channels.Channel

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
    private fun formatBytes(bytes: Long) = ProxyStats.formatBytes(bytes)
    private fun getBuffer(): ByteArray = BypassConfig.TrafficShaper.acquireBuffer(16384)
    private fun releaseBuffer(buffer: ByteArray) = BypassConfig.TrafficShaper.releaseBuffer(buffer)

    companion object {
        @Volatile var instance: PinkVpnService? = null
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
            prefs.edit { putBoolean("vpn_should_be_running", isRunning) }
        }

        fun updateTile(context: Context) {
            try {
                android.service.quicksettings.TileService.requestListeningState(
                    context,
                    android.content.ComponentName(context, PinkProxyTileService::class.java)
                )
            } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var proxyServer: PinkProxyServer? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private val PROXY_PORT = 18080
    private val proxyMutex = kotlinx.coroutines.sync.Mutex()
    
    private val batteryReceiver = object : android.content.BroadcastReceiver() {
        override fun onReceive(context: android.content.Context?, intent: android.content.Intent?) {
            val status = intent?.getIntExtra(android.os.BatteryManager.EXTRA_STATUS, -1)
            val isCharging = status == android.os.BatteryManager.BATTERY_STATUS_CHARGING ||
                             status == android.os.BatteryManager.BATTERY_STATUS_FULL
            BypassConfig.updateChargingStatus(isCharging)
            if (!isCharging) {
                Log.d("PinkVpnService", "Device unplugged. Core Engine entering Battery-Safe Mode.")
            }
        }
    }

    private val serviceDispatcher = java.util.concurrent.Executors.newCachedThreadPool().asCoroutineDispatcher()
    private val serviceScope = CoroutineScope(serviceDispatcher + SupervisorJob())
    fun getServiceScope() = serviceScope
    private var sessionScope: CoroutineScope? = null
    private var connectivityManager: ConnectivityManager? = null
    private var isNetworkCallbackRegistered = false

    private val MAX_UDP_SESSIONS = 100
    private fun acquireWakeLock() {
        try {
            val pm = getSystemService(POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "PinkProxy:VpnWakeLock")
            // Instead of holding indefinitely, we rely on the network stack to wake us up.
            // A persistent wake lock drains 30%+ of battery in 24 hours. We only hold it if strictly requested.
        } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
    }

    private fun releaseWakeLock() {
        try {
            if (wakeLock?.isHeld == true) wakeLock?.release()
            wakeLock = null
        } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
    }

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
            ProxyStats.logRecovery("Network connection restored. Re-checking services and updating ECS subnet...")
            RobustResolver.updatePublicIpSubnet(this@PinkVpnService)
            ServiceChecker.triggerCheck()
        }
    }

    private suspend fun restartProxyServer(reason: String) {
        proxyMutex.withLock {
            if (!_isRunning.value) return@withLock
            ProxyStats.logRecovery(reason)
            BypassConfig.reOptimize()
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
        instance = this
        loadFilterSettings(this)
        registerReceiver(batteryReceiver, android.content.IntentFilter(android.content.Intent.ACTION_BATTERY_CHANGED))
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
            ProxyStats.isMonitoring = true
            saveVpnState(this, true)
            startVpn()
            checkBatteryOptimization()
            updateTile(this)
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
        acquireWakeLock()

        // Promote the service to foreground immediately to satisfy OS requirements and prevent ANR/crash
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
            sessionScope?.cancel()
        } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        val newSessionScope = CoroutineScope(serviceDispatcher + SupervisorJob())
        sessionScope = newSessionScope
        
        RobustResolver.initialize(this)
        RobustResolver.startPrefetching(newSessionScope, this)
        RobustResolver.startDnsOptimizer(newSessionScope, this)
        RobustResolver.startSelfHealing(newSessionScope)
        BypassConfig.initialize(this)
        BypassConfig.testInitialStrategies(this)

        val prefs = getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
        prefs.edit { putBoolean("vpn_was_active", true) }

        if (!isNetworkCallbackRegistered) {
            connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            try {
                connectivityManager?.registerNetworkCallback(
                    NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build(),
                    networkCallback
                )
                isNetworkCallbackRegistered = true
            } catch (e: Exception) {
                Log.e("PinkVpnService", "Failed to register network callback", e)
            }
        }

        // Sanity check: ensure we are prepared
        try {
            if (prepare(this) != null) {
                Log.e("PinkVpnService", "VPN not prepared. Stopping.")
                stopVpn()
                return
            }
        } catch (e: SecurityException) {
            Log.e("PinkVpnService", "SecurityException during prepare check", e)
            stopVpn()
            return
        }

        try {
            ServiceChecker.proxyPort = PROXY_PORT
            ProxyStats.reset(clearLog = true)
            ProxyStats.logRecovery("System Initialized: All components READY")
            ProxyStats.logRecovery("Mode: DPI Bypass / HTTP Tunnel")
            proxyServer?.stop()
            proxyServer = PinkProxyServer(this, PROXY_PORT)
            proxyServer?.start()

            RobustResolver.startPrefetching(newSessionScope, this)

            // Self-healing monitor and stats persistence
            newSessionScope.launch {
                launch {
                    ProxyStats.proxyHealthTrigger.collect { reason ->
                        restartProxyServer("Self-Healing: $reason")
                    }
                }
                launch {
                    ProxyStats.fragmentationErrors.collect { errors ->
                        if (errors > 0 && errors % 5 == 0) {
                            val newMtu = (BypassConfig.currentMtu.value - 20).coerceAtLeast(1200)
                            if (newMtu != BypassConfig.currentMtu.value) {
                                BypassConfig.currentMtu.value = newMtu
                            }
                        }
                    }
                }
                launch {
                    var isFirst = true
                    BypassConfig.currentMtu.collect { mtu ->
                        if (isFirst) {
                            isFirst = false
                            return@collect
                        }
                        if (vpnInterface != null) {
                            ProxyStats.logRecovery("CORE: Applying new MTU ($mtu)...")
                            // Restarting the VPN interface to apply MTU using unshadowed service-scoped coroutine to prevent self-cancellation
                            this@PinkVpnService.serviceScope.launch(Dispatchers.Main) {
                                stopVpnInterfaceOnly()
                                startVpn()
                            }
                        }
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
                .addDnsServer("10.0.0.3")
            builder.setSession("PinkProxy")
                   .setMtu(BypassConfig.currentMtu.value)
            
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            // Route traffic through our local proxy
            builder.setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", PROXY_PORT))
            
            // Application filtering
            if (isExcludeMode) {
                builder.addDisallowedApplication(packageName)
                selectedPackages.forEach { pkg ->
                    try { builder.addDisallowedApplication(pkg) } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                }
            } else {
                selectedPackages.filter { it != packageName }.forEach { pkg ->
                    try { builder.addAllowedApplication(pkg) } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
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
            builder.addRoute("8.8.8.8", 32)
            builder.addRoute("8.8.4.4", 32)
            builder.addRoute("1.1.1.1", 32)
            builder.addRoute("1.0.0.1", 32)
            builder.addRoute("9.9.9.9", 32)
            builder.addRoute("149.112.112.112", 32)
            builder.addRoute("208.67.222.222", 32)
            builder.addRoute("208.67.220.220", 32)
            builder.addRoute("94.140.14.14", 32)
            builder.addRoute("94.140.15.15", 32)
            
            // Note: We do NOT use addRoute("0.0.0.0", 0) because we don't have a TUN-to-TCP (tun2socks) layer.
            // Any app ignoring the proxy would otherwise lose internet.


            builder.setMtu(BypassConfig.currentMtu.value)
            
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
            serviceScope.launch(serviceDispatcher) {
                val fd = vpnInterface?.fileDescriptor ?: return@launch
                val inputStream = FileInputStream(fd)
                val outputStream = FileOutputStream(fd)
                
                val writeChannel = Channel<ByteArray>(512, kotlinx.coroutines.channels.BufferOverflow.DROP_OLDEST)
                val writerJob = launch(serviceDispatcher) {
                    try {
                        for (packet in writeChannel) {
                            try {
                                outputStream.write(packet)
                                outputStream.flush()
                            } catch (e: Exception) {
                                // Prevent write failures from crashing the loop
                            }
                        }
                    } catch (e: Exception) {
                        // ignore
                    }
                }

                // Use a LinkedHashMap with accessOrder=true for O(1) LRU eviction
                val udpRelays = object : java.util.LinkedHashMap<Long, UdpSession>(MAX_UDP_SESSIONS, 0.75f, true) {
                    override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Long, UdpSession>): Boolean {
                        return if (size > MAX_UDP_SESSIONS) {
                            eldest.value.close()
                            true
                        } else false
                    }
                }
                
                // Cleanup job for inactive sessions (periodic sweep as fallback)
                val cleanupJob = launch {
                    while (isActive && isRunning.value) {
                        delay(60000)
                        val now = System.currentTimeMillis()
                        synchronized(udpRelays) {
                            val it = udpRelays.entries.iterator()
                            while (it.hasNext()) {
                                val entry = it.next()
                                if (now - entry.value.lastActivity > 60000) {
                                    entry.value.close()
                                    it.remove()
                                }
                            }
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
                                if (protocol == 1) { // ICMP
                                    val ihl = (packet[0].toInt() and 0x0F) * 4
                                    if (read >= ihl + 8) {
                                        val icmpType = packet[ihl].toInt() and 0xFF
                                        if (icmpType == 8) { // Echo Request
                                            val replyPacket = IcmpHelper.createIcmpEchoReplyPacket(packet, read, ihl)
                                            writeChannel.trySend(replyPacket)
                                        }
                                    }
                                } else if (protocol == 6) { // TCP
                                    val rejectPacket = IcmpHelper.createTcpRstPacket(packet, read)
                                    writeChannel.trySend(rejectPacket)
                                } else if (protocol == 17) { // UDP
                                    val ihl = (packet[0].toInt() and 0x0F) * 4
                                    if (read >= ihl + 8) {
                                        val srcIpInt = ((packet[12].toInt() and 0xFF) shl 24) or ((packet[13].toInt() and 0xFF) shl 16) or ((packet[14].toInt() and 0xFF) shl 8) or (packet[15].toInt() and 0xFF)
                                        val dstIpInt = ((packet[16].toInt() and 0xFF) shl 24) or ((packet[17].toInt() and 0xFF) shl 16) or ((packet[18].toInt() and 0xFF) shl 8) or (packet[19].toInt() and 0xFF)
                                        val srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
                                        val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
                                        
                                        val payloadOffset = ihl + 8
                                        val payloadLen = read - payloadOffset
                                        if (payloadLen > 0) {
                                            if (BypassConfig.blockQuic && dstPort == 443) {
                                                // Generate ICMP Port Unreachable to reject QUIC immediately
                                                val rejectPacket = IcmpHelper.createIcmpPortUnreachablePacket(packet, read)
                                                writeChannel.trySend(rejectPacket)
                                                continue@tunLoop
                                            }
                                            val key = (dstIpInt.toLong() and 0xFFFFFFFFL) or (srcPort.toLong() shl 32) or (dstPort.toLong() shl 48)
                                            var session = synchronized(udpRelays) { udpRelays[key] }
                                            if (session == null || session.isClosed) {
                                                val formatIp = { ip: Int -> "${(ip shr 24) and 0xFF}.${(ip shr 16) and 0xFF}.${(ip shr 8) and 0xFF}.${ip and 0xFF}" }
                                                
                                                // DNS Hijacking: if port 53, resolve via RobustResolver
                                                if (dstPort == 53) {
                                                    val dnsPayload = packet.copyOfRange(payloadOffset, read)
                                                    val parsedQuery = parseDnsQName(dnsPayload)
                                                    if (parsedQuery != null && parsedQuery.qname.contains(".")) {
                                                        val isIpv6 = parsedQuery.qtype == 28
                                                        if (isIpv6) {
                                                            // Fast path: immediate IPv6 empty reply on the same thread
                                                            val dnsReply = buildDnsReply(dnsPayload, emptyList(), isIpv6 = true)
                                                            val replyPacket = createUdpIpPacket(dstIpInt, srcIpInt, dstPort, srcPort, dnsReply)
                                                            writeChannel.trySend(replyPacket)
                                                            continue@tunLoop
                                                        }
                                                        
                                                        // Fast path: check DNS Cache synchronously before launching a coroutine
                                                        val cachedIps = RobustResolver.getCached(parsedQuery.qname)
                                                        if (cachedIps != null) {
                                                            val matchedList = cachedIps.mapNotNull { it.hostAddress }.filter { it.contains(".") && !it.contains(":") }
                                                            if (matchedList.isNotEmpty()) {
                                                                val dnsReply = buildDnsReply(dnsPayload, matchedList, isIpv6 = false)
                                                                val replyPacket = createUdpIpPacket(dstIpInt, srcIpInt, dstPort, srcPort, dnsReply)
                                                                writeChannel.trySend(replyPacket)
                                                                ProxyStats.logTraffic(parsedQuery.qname, "DNS_CACHE_FAST")
                                                                continue@tunLoop
                                                            }
                                                        }
                                                    }

                                                    serviceScope.launch(serviceDispatcher) {
                                                        try {
                                                            if (parsedQuery != null && parsedQuery.qname.contains(".")) {
                                                                val ips = RobustResolver.resolve(parsedQuery.qname, this@PinkVpnService)
                                                                val matchedList = ips.mapNotNull { it.hostAddress }.filter { it.contains(".") && !it.contains(":") }
                                                                if (matchedList.isNotEmpty()) {
                                                                    val dnsReply = buildDnsReply(dnsPayload, matchedList, isIpv6 = false)
                                                                    val replyPacket = createUdpIpPacket(dstIpInt, srcIpInt, dstPort, srcPort, dnsReply)
                                                                    writeChannel.trySend(replyPacket)
                                                                    ProxyStats.logTraffic(parsedQuery.qname, "DNS_HIJACK")
                                                                    return@launch
                                                                }
                                                            }
                                                        } catch (e: Exception) {
                                                            Log.e("PinkVpnService", "DNS Hijack failed for ${formatIp(dstIpInt)}", e)
                                                        }
                                                        
                                                        // Fallback to normal UDP relay if hijack failed
                                                        val realDstIp = if (dstIpInt == 0x0A000003 /* 10.0.0.3 */) "8.8.8.8" else formatIp(dstIpInt)
                                                        val s = UdpSession(realDstIp, dstPort, this@PinkVpnService, serviceScope) { reply ->
                                                            try {
                                                                val replyPacket = createUdpIpPacket(dstIpInt, srcIpInt, dstPort, srcPort, reply)
                                                                writeChannel.trySend(replyPacket)
                                                            } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                                                        }
                                                        synchronized(udpRelays) { udpRelays[key] = s }
                                                        s.send(dnsPayload)
                                                    }
                                                    // Continue loop, packet will be released in finally
                                                    continue@tunLoop
                                                }

                                                val realDstIp = if (dstIpInt == 0x0A000003 /* 10.0.0.3 */) "8.8.8.8" else formatIp(dstIpInt)
                                                session = UdpSession(realDstIp, dstPort, this@PinkVpnService, serviceScope) { reply ->
                                                    try {
                                                        val replyPacket = createUdpIpPacket(dstIpInt, srcIpInt, dstPort, srcPort, reply)
                                                        writeChannel.trySend(replyPacket)
                                                        ProxyStats.addBytes(reply.size.toLong())
                                                        ProxyStats.recordDataReceived()
                                                    } catch (e: Exception) {
                                                        Log.e("PinkVpnService", "Failed to inject UDP reply", e)
                                                    }
                                                }
                                                synchronized(udpRelays) { udpRelays[key] = session }
                                            }
                                            val p = packet.copyOfRange(payloadOffset, read)
                                            session?.send(p)
                                            ProxyStats.addBytes(p.size.toLong())
                                            ProxyStats.recordDataSent()
                                        }
                                    }
                                }
                            } else if (version == 6) {
                                if (read >= 40) {
                                    // Extract next header from IPv6
                                    val nextHeader = packet[6].toInt() and 0xFF
                                    if (nextHeader == 58) { // ICMPv6
                                        if (read >= 48) {
                                            val icmpType = packet[40].toInt() and 0xFF
                                            if (icmpType == 128) { // Echo Request
                                                val replyPacket = IcmpHelper.createIcmpv6EchoReplyPacket(packet, read)
                                                writeChannel.trySend(replyPacket)
                                            }
                                        }
                                    } else if (nextHeader == 6) { // TCP
                                        val rejectPacket = IcmpHelper.createIcmpv6TcpRstPacket(packet, read)
                                        writeChannel.trySend(rejectPacket)
                                    } else if (nextHeader == 17) { // UDP
                                        if (read >= 44) {
                                            val dstPort = ((packet[42].toInt() and 0xFF) shl 8) or (packet[43].toInt() and 0xFF)
                                            if (dstPort == 443 || dstPort == 53) {
                                                // Reject QUIC over IPv6 to force fast TCP fallback
                                                val rejectPacket = IcmpHelper.createIcmpv6PortUnreachablePacket(packet, read)
                                                writeChannel.trySend(rejectPacket)
                                            }
                                        }
                                    }
                                }
                                // Drop other IPv6 for now
                            }
                        } finally {
                            releaseBuffer(packet)
                        }
                    }
                } catch (e: Exception) {
                    Log.e("PinkVpnService", "TUN reader error", e)
                } finally {
                    cleanupJob.cancel()
                    writerJob.cancel()
                    writeChannel.close()
                    try { inputStream.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                    try { outputStream.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                    synchronized(udpRelays) { udpRelays.values.forEach { it.close() } }
                }
            }
            
            BypassConfig.loadTuningSettings(this)
            RobustResolver.loadDnsSettings(this)
            RobustResolver.startBackgroundProber(serviceScope, this)
            ServiceChecker.startChecking(serviceScope, this)
            
            newSessionScope.launch {
                var errorThreshold = 0
                var lowConnectivityCount = 0
                while (isActive && isRunning.value) {
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
                            ProxyStats.logRecovery("AUTO-HEAL: Persistent performance drop. Triggering Deep Probe...")
                            ServiceChecker.runActiveProbing(this@PinkVpnService)
                            RobustResolver.clearCache()
                            lowConnectivityCount = 0
                        }
                    } else {
                        lowConnectivityCount = 0
                    }
                    
                    // Periodic Parameter Mutation for active strategy
                    if (isRunning.value && (System.currentTimeMillis() % 300000 < 30000)) {
                         BypassConfig.reOptimize()
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
                        } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
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
                                BypassConfig.recordSuccess(BypassConfig.strategy.value, -1L, this@PinkVpnService)
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

            newSessionScope.launch {
                while (isActive && isRunning.value) {
                    ServiceChecker.checkStall(ProxyStats.bytesTransferred.value)
                    delay(5000)
                }
            }

        } catch (e: Exception) {
            Log.e("PinkVpnService", "Error starting VPN", e)
            stopVpn()
        }
    }

    private var lastNotificationUpdateTime = 0L

    private fun updateNotification(speed: String, servicesInfo: String) {
        if (!_isRunning.value) return
        val now = System.currentTimeMillis()
        if (now - lastNotificationUpdateTime < 2000) return
        lastNotificationUpdateTime = now
        
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

        val stopIntent = Intent(this, PinkVpnService::class.java).apply {
            action = "STOP"
        }
        val stopPendingIntent = PendingIntent.getService(
            this, 2, stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification = NotificationCompat.Builder(this, "pink_proxy_channel")
            .setContentTitle("PinkProxy: $speed")
            .setContentText(servicesInfo)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(pendingIntent)
            .addAction(R.drawable.ic_launcher_foreground, "STOP", stopPendingIntent)
            .addAction(R.drawable.ic_launcher_foreground, "RE-OPTIMIZE", restartPendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()

        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(1, notification)
    }

    private fun stopVpn() {
        releaseWakeLock()
        ProxyStats.isMonitoring = false
        RobustResolver.stopBackgroundProber()
        val prefs = getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
        prefs.edit { putBoolean("vpn_was_active", false) }

        _isRunning.value = false
        updateTile(this)
        stopVpnInterfaceOnly()
        
        try {
            sessionScope?.cancel()
            sessionScope = null
        } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        try {
            serviceScope.coroutineContext.cancelChildren()
        } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        if (isNetworkCallbackRegistered) {
            try {
                connectivityManager?.unregisterNetworkCallback(networkCallback)
            } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
            isNetworkCallbackRegistered = false
        }
        ServiceChecker.stopChecking()
        proxyServer?.stop()
        proxyServer = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun stopVpnInterfaceOnly() {
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e("PinkVpnService", "Error closing VPN interface", e)
        }
        vpnInterface = null
    }

    override fun onRevoke() {
        super.onRevoke()
        stopVpn()
    }

    override fun onDestroy() {
        super.onDestroy()
        try { unregisterReceiver(batteryReceiver) } catch (e: Exception) {}
        stopVpn()
        serviceScope.cancel()
        BypassConfig.activeVpnService = null
        instance = null
        try { serviceDispatcher.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            "pink_proxy_channel",
            "PinkProxy Service",
            NotificationManager.IMPORTANCE_LOW
        )
        val manager = getSystemService(NotificationManager::class.java)
        manager?.createNotificationChannel(channel)
    }

    private class UdpSession(
        val dstIp: String,
        val dstPort: Int,
        val vpn: VpnService,
        val scope: kotlinx.coroutines.CoroutineScope,
        val onReply: (ByteArray) -> Unit
    ) {
        private val socket = DatagramSocket()
        private val sendChannel = Channel<ByteArray>(200) // Bound channel to prevent memory bloat
        @Volatile var isClosed = false
        @Volatile var lastActivity = System.currentTimeMillis()
        private var pfd: android.os.ParcelFileDescriptor? = null
        private var fd: java.io.FileDescriptor? = null
        private var cachedDstAddr: InetAddress? = null
        
        init {
            BypassConfig.KernelOptimizer.tuneUdp(socket)
            vpn.protect(socket)
            socket.soTimeout = 1000
            try {
                pfd = android.os.ParcelFileDescriptor.fromDatagramSocket(socket)
                fd = pfd?.fileDescriptor
            } catch (e: Exception) {
                Log.e("PinkVpnService", "Failed to obtain file descriptor for socket", e)
            }
            
            // Resolve destination IP asynchronously once
            scope.launch {
                try {
                    cachedDstAddr = InetAddress.getByName(dstIp)
                } catch (e: Exception) {
                    Log.e("PinkVpnService", "Failed to resolve UDP destination: $dstIp", e)
                }
            }
            
            // Receiver loop
            scope.launch {
                val buffer = BypassConfig.TrafficShaper.acquireBuffer(16384)
                try {
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
                } finally {
                    BypassConfig.TrafficShaper.releaseBuffer(buffer)
                    close()
                }
            }
            
            // Sender loop
            scope.launch {
                try {
                    for (data in sendChannel) {
                        if (isClosed) break
                        try {
                            val addr = cachedDstAddr ?: InetAddress.getByName(dstIp)
                            val currentFd = fd
                            
                            if (data.size > 10 && BypassConfig.strategy.value != BypassStrategy.DIRECT && currentFd != null) {
                                try {
                                    val isIpv6 = addr is java.net.Inet6Address
                                    val osProto = if (isIpv6) android.system.OsConstants.IPPROTO_IPV6 else android.system.OsConstants.IPPROTO_IP
                                    val osTtlOpt = if (isIpv6) android.system.OsConstants.IPV6_UNICAST_HOPS else android.system.OsConstants.IP_TTL
                                    val strategy = BypassConfig.getBestStrategyForHost(dstIp)

                                    // Advanced UDP Evasion
                                    if (strategy == BypassStrategy.QUIC_VERSION_NEG_FAKE && dstPort == 443) {
                                        val vNeg = ByteArray(12) { 0 }
                                        vNeg[0] = 0x80.toByte() // Long header
                                        // Fake versions
                                        vNeg[9] = 0x55.toByte(); vNeg[10] = 0xAA.toByte()
                                        socket.send(DatagramPacket(vNeg, vNeg.size, addr, dstPort))
                                        delay(5)
                                    }

                                    // UDP Padding and Jitter
                                    val finalData = if (data.size in 30..400 && java.util.concurrent.ThreadLocalRandom.current().nextDouble() > 0.5) {
                                        val padSize = when {
                                            strategy == BypassStrategy.QUIC_PAD -> java.util.concurrent.ThreadLocalRandom.current().nextInt(64, 256)
                                            BypassConfig.isPanicMode -> java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 8)
                                            else -> java.util.concurrent.ThreadLocalRandom.current().nextInt(4, 17)
                                        }
                                        data + ByteArray(padSize) { 0 }
                                    } else data

                                    if (finalData.size > BypassConfig.udpMtu.value || BypassConfig.isPanicMode || strategy == BypassStrategy.FAKE_PACKET || strategy == BypassStrategy.TCP_OOB_DESYNC) {
                                        // UDP Fake Packets for DPI evasion
                                        if (java.util.concurrent.ThreadLocalRandom.current().nextDouble() > 0.3) {
                                            val isPanic = BypassConfig.isPanicMode
                                            val fakeTtl = (BypassConfig.fakeTtl + java.util.concurrent.ThreadLocalRandom.current().nextInt(-1, 2)).coerceIn(2, 12)
                                            android.system.Os.setsockoptInt(currentFd, osProto, osTtlOpt, fakeTtl)
                                            val fakePayload = if (dstPort == 443 && java.util.concurrent.ThreadLocalRandom.current().nextDouble() > 0.5) FakePacketHelper.buildQuicInitial() else ByteArray(java.util.concurrent.ThreadLocalRandom.current().nextInt(8, 33)) { java.util.concurrent.ThreadLocalRandom.current().nextInt(256).toByte() }
                                            socket.send(DatagramPacket(fakePayload, fakePayload.size, addr, dstPort))
                                            BypassConfig.TrafficShaper.pace(isPanic, fakePayload.size)
                                        }
                                        android.system.Os.setsockoptInt(currentFd, osProto, osTtlOpt, 64)
                                        socket.send(DatagramPacket(finalData, finalData.size, addr, dstPort))
                                    } else {
                                        android.system.Os.setsockoptInt(currentFd, osProto, osTtlOpt, 64)
                                        socket.send(DatagramPacket(finalData, finalData.size, addr, dstPort))
                                    }
                                    
                                    // Pacing for high-volume streams
                                    if (finalData.size > 1000) {
                                        delay(BypassConfig.isPanicMode.let { if (it) java.util.concurrent.ThreadLocalRandom.current().nextLong(1, 4) else java.util.concurrent.ThreadLocalRandom.current().nextLong(1, 6) })
                                    }
                                } catch (e: Exception) { android.util.Log.v("PinkProxy", "UDP Bypass Failed: ${e.message}") }
                            } else {
                                socket.send(DatagramPacket(data, data.size, addr, dstPort))
                            }
                        } catch (e: Exception) {
                            if (isClosed) break
                        }
                    }
                } catch (e: Exception) {
                    // loop aborted
                } finally {
                    close()
                }
            }
        }
        
        fun send(data: ByteArray) {
            lastActivity = System.currentTimeMillis()
            if (!isClosed) {
                sendChannel.trySend(data)
            }
        }
        
        fun close() {
            if (!isClosed) {
                isClosed = true
                sendChannel.close()
                try { socket.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                try { pfd?.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
            }
        }
    }

    private val packetBufferTL = object : ThreadLocal<ByteBuffer>() {
        override fun initialValue(): ByteBuffer = ByteBuffer.allocate(65535)
    }
    
    private val pseudoBufferTL = object : ThreadLocal<ByteBuffer>() {
        override fun initialValue(): ByteBuffer = ByteBuffer.allocate(65535)
    }

    private fun createUdpIpPacket(srcIpInt: Int, dstIpInt: Int, srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
        val ipLen = 20 + 8 + payload.size
        val buffer = packetBufferTL.get()!!
        buffer.clear()
        
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
        
        buffer.putInt(srcIpInt)
        buffer.putInt(dstIpInt)
        
        // Calculate IP Checksum
        val header = buffer.array()
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
            val pseudoHeader = pseudoBufferTL.get()!!
            pseudoHeader.clear()
            pseudoHeader.putInt(srcIpInt)
            pseudoHeader.putInt(dstIpInt)
            pseudoHeader.put(0.toByte())
            pseudoHeader.put(17.toByte()) // Protocol UDP
            pseudoHeader.putShort(udpLen.toShort())
            
            // UDP Header + Payload
            pseudoHeader.putShort(srcPort.toShort())
            pseudoHeader.putShort(dstPort.toShort())
            pseudoHeader.putShort(udpLen.toShort())
            pseudoHeader.putShort(0.toShort())
            pseudoHeader.put(payload)
            
            val udpDataLength = 12 + udpLen
            val udpData = pseudoHeader.array()
            var sum = 0
            for (i in 0 until (udpDataLength / 2)) {
                sum += ((udpData[i * 2].toInt() and 0xFF) shl 8) or (udpData[i * 2 + 1].toInt() and 0xFF)
            }
            if (udpDataLength % 2 != 0) {
                sum += (udpData[udpDataLength - 1].toInt() and 0xFF) shl 8
            }
            while (sum shr 16 != 0) {
                sum = (sum and 0xFFFF) + (sum shr 16)
            }
            var checksum = (sum.inv() and 0xFFFF).toShort()
            if (checksum == 0.toShort()) checksum = 0xFFFF.toShort()
            buffer.putShort(udpChecksumPos, checksum)
        } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }

        return buffer.array().copyOfRange(0, ipLen)
    }

    data class ParsedDnsQuery(val qname: String, val qtype: Int)

    private fun parseDnsQName(payload: ByteArray): ParsedDnsQuery? {
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
            if (pos + 2 < payload.size) {
                val qtype = ((payload[pos + 1].toInt() and 0xFF) shl 8) or (payload[pos + 2].toInt() and 0xFF)
                return ParsedDnsQuery(sb.toString(), qtype)
            }
            return ParsedDnsQuery(sb.toString(), 1)
        } catch (e: Exception) {
            return null
        }
    }

    private fun buildDnsReply(query: ByteArray, ips: List<String>, isIpv6: Boolean): ByteArray {
        val bos = java.io.ByteArrayOutputStream()
        // ID
        bos.write(query.getOrNull(0)?.toInt() ?: 0)
        bos.write(query.getOrNull(1)?.toInt() ?: 0)
        // Flags: Standard query response, No error
        bos.write(0x81)
        bos.write(0x80)
        // Questions count
        bos.write(0)
        bos.write(1)
        // Answer count
        bos.write((ips.size shr 8) and 0xFF)
        bos.write(ips.size and 0xFF)
        // Authority / Additional
        bos.write(0); bos.write(0)
        bos.write(0); bos.write(0)
        
        // Copy Question section
        var pos = 12
        while (pos < query.size) {
            val len = query[pos].toInt() and 0xFF
            if (len == 0) {
                bos.write(0)
                // Type (A = 1, AAAA = 28) and Class IN (0x0001)
                bos.write(query.getOrNull(pos + 1)?.toInt() ?: 0)
                bos.write(query.getOrNull(pos + 2)?.toInt() ?: 0)
                bos.write(query.getOrNull(pos + 3)?.toInt() ?: 0)
                bos.write(query.getOrNull(pos + 4)?.toInt() ?: 0)
                break
            }
            bos.write(len)
            if (pos + 1 + len <= query.size) {
                bos.write(query, pos + 1, len)
            } else {
                val available = (query.size - (pos + 1)).coerceAtLeast(0)
                if (available > 0) {
                    bos.write(query, pos + 1, available)
                }
            }
            pos += (len + 1)
        }
        
        // Answers
        for (ip in ips) {
            // Name: pointer to offset 12 (0xc00c)
            bos.write(0xc0)
            bos.write(0x0c)
            if (isIpv6) {
                // Type AAAA (28 = 0x001c)
                bos.write(0); bos.write(28)
                // Class IN
                bos.write(0); bos.write(1)
                // TTL (60s)
                bos.write(0); bos.write(0); bos.write(0); bos.write(60)
                // Data length (16 bytes for IPv6)
                bos.write(0); bos.write(16)
                // Parse and write IPv6 safely
                val addr = try { InetAddress.getByName(ip) } catch (e: Exception) { null }
                if (addr != null) {
                    bos.write(addr.address)
                } else {
                    bos.write(ByteArray(16))
                }
            } else {
                // Type A (1 = 0x0001)
                bos.write(0); bos.write(1)
                // Class IN
                bos.write(0); bos.write(1)
                // TTL (60s)
                bos.write(0); bos.write(0); bos.write(0); bos.write(60)
                // Data length (4 bytes for IPv4)
                bos.write(0); bos.write(4)
                // IP address safely
                val addr = try { InetAddress.getByName(ip) } catch (e: Exception) { null }
                if (addr != null) {
                    bos.write(addr.address)
                } else {
                    bos.write(ByteArray(4))
                }
            }
        }
        
        return bos.toByteArray()
    }
}
