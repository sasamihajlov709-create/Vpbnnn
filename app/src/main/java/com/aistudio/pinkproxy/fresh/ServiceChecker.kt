package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.net.HttpURLConnection
import java.net.URL
import java.net.Proxy
import java.net.InetSocketAddress

object ServiceChecker {
    var proxyPort = 18080
    data class ServiceStatus(val name: String, val url: String, val isUp: Boolean, val latencyMs: Long)
    data class GlobalStatus(val isProxyRunning: Boolean, val services: List<ServiceStatus>)

    private val _statuses = MutableStateFlow<List<ServiceStatus>>(emptyList())
    val statuses: StateFlow<List<ServiceStatus>> = _statuses.asStateFlow()

    private val _proxyHealth = MutableStateFlow(true)
    val proxyHealth: StateFlow<Boolean> = _proxyHealth.asStateFlow()

    private val _lastCheckTime = MutableStateFlow(0L)
    val lastCheckTime: StateFlow<Long> = _lastCheckTime.asStateFlow()

    private val _internetAvailable = MutableStateFlow(true)
    val internetAvailable: StateFlow<Boolean> = _internetAvailable.asStateFlow()

    private val _connectivityScore = MutableStateFlow(0)
    val connectivityScore: StateFlow<Int> = _connectivityScore.asStateFlow()

    private val _isStalled = MutableStateFlow(false)
    val isStalled: StateFlow<Boolean> = _isStalled.asStateFlow()

    private var lastTotalBytes = 0L
    private var lastStallCheck = System.currentTimeMillis()

    fun checkStall(currentBytes: Long) {
        val now = System.currentTimeMillis()
        if (now - lastStallCheck > 90000) { // Check every 90 seconds (was 15s)
            val diff = currentBytes - lastTotalBytes
            val activeConns = ProxyStats.activeConnections.value
            // Stall is only if we have high active connections and no data for a long time,
            // or high error rate. Long polling can legitimately hold connections.
            val stalled = activeConns > 5 && diff == 0L
            _isStalled.value = stalled
            
            if (stalled && ProxyStats.successRate.value < 70) {
                ProxyStats.logRecovery("WARNING: Traffic stall detected (many active connections, 0 bytes moved for 90s, low success rate). Self-healing started...")
                RobustResolver.clearCache()
                BypassConfig.panicOptimize()
                appContext?.let { ctx ->
                    runActiveProbing(ctx)
                }
            }
            
            lastTotalBytes = currentBytes
            lastStallCheck = now
        }
    }

    private var job: Job? = null
    private var internalScope: CoroutineScope? = null
    private val _isProbingState = MutableStateFlow(false)
    val isProbingState: StateFlow<Boolean> = _isProbingState.asStateFlow()
    private val isProbing = java.util.concurrent.atomic.AtomicBoolean(false)
    private var lastProbeTime = 0L
    private var appContext: android.content.Context? = null
    
    fun triggerCheck() {
        val scope = internalScope ?: return
        val services = _statuses.value.map { it.name to it.url }
        if (services.isNotEmpty()) {
            scope.launch { checkServices(services) }
        }
    }

    private suspend fun checkServices(servicesToCheck: List<Pair<String, String>>) {
        val proxyResponsive = java.util.concurrent.atomic.AtomicBoolean(true)
        var internetUp = false

        // Baseline check: multiple reliable domains (without proxy)
        val baselineDomains = listOf("https://ya.ru", "https://www.google.com/generate_204", "https://www.apple.com/library/test/success.html")
        for (domain in baselineDomains) {
            var conn: HttpURLConnection? = null
            try {
                conn = URL(domain).openConnection(java.net.Proxy.NO_PROXY) as HttpURLConnection
                if (conn is javax.net.ssl.HttpsURLConnection) {
                    val sslContext = javax.net.ssl.SSLContext.getInstance("TLS")
                    sslContext.init(null, null, null)
                    PinkVpnService.instance?.let { vpn ->
                        conn.sslSocketFactory = ProtectedSSLSocketFactory(sslContext.socketFactory, vpn)
                    }
                }
                conn.connectTimeout = 3000
                conn.readTimeout = 3000
                conn.requestMethod = "GET"
                if (conn.responseCode in 200..499) {
                    internetUp = true
                    
                    // Hijack Detection: If google.com resolves to something suspicious
                    if (domain.contains("google.com")) {
                        try {
                            val addr = java.net.InetAddress.getByName("google.com")
                            val hostName = addr.canonicalHostName.lowercase()
                            if (hostName.contains(".ru") || hostName.contains("rostelecom") || hostName.contains("mts.ru")) {
                                ProxyStats.logRecovery("ALERT: DNS Hijacking Detected. Forcing Robust DNS Mode.")
                                RobustResolver.dnsMode = "Smart DoH" // Force DoH
                            }
                        } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                    }
                    
                    break
                }
            } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") } finally {
                try { conn?.inputStream?.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                try { conn?.errorStream?.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                try { conn?.disconnect() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
            }
        }
        _internetAvailable.value = internetUp
        if (!internetUp) {
            _statuses.value = servicesToCheck.map { ServiceStatus(it.first, it.second, false, 0) }
            _connectivityScore.value = 0
            _proxyHealth.value = proxyResponsive.get()
            return
        }

        // Deep Proxy Integrity Check
        val relayResponsive = try {
            val sock = java.net.Socket()
            sock.connect(java.net.InetSocketAddress("127.0.0.1", proxyPort), 1000)
            sock.close()
            true
        } catch (e: Exception) {
            false
        }
        _proxyHealth.value = relayResponsive
        
        if (!relayResponsive && internetUp) {
            ProxyStats.forceRecovery("Local proxy port $proxyPort unresponsive during check")
        }

        val results = coroutineScope {
            servicesToCheck.map { (name, url) ->
                async {
                    val start = System.currentTimeMillis()
                    var isUp = false
                    var attempt = 0
                    var successfulLatency = 0L
                    while (attempt < 2 && !isUp) {
                        attempt++
                        var connection: HttpURLConnection? = null
                        val attemptStart = System.currentTimeMillis()
                        try {
                            val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", proxyPort))
                            connection = URL(url).openConnection(proxy) as HttpURLConnection
                            connection.connectTimeout = 8000
                            connection.readTimeout = 8000
                            connection.instanceFollowRedirects = true
                            connection.requestMethod = "GET"
                            connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                            
                            val code = connection.responseCode
                            isUp = (code in 200..499)
                            
                            val attemptDuration = System.currentTimeMillis() - attemptStart
                            if (isUp) {
                                successfulLatency = attemptDuration
                            }
                            
                            // Throttling detection: if latency > 6s for critical services, consider it "down"
                            val latencyThreshold = if (name.contains("Stream")) 4000 else 6000
                            if (isUp && (name.contains("YouTube") || name.contains("Telegram")) && attemptDuration > latencyThreshold) {
                                isUp = false 
                            }
                        } catch (e: Exception) {
                            isUp = false
                            if (e is java.net.ConnectException || e.message?.contains("127.0.0.1") == true || e.message?.contains("refused") == true) {
                                proxyResponsive.set(false)
                            }
                        } finally {
                            try { connection?.inputStream?.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                            try { connection?.errorStream?.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                            try { connection?.disconnect() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                        }
                        if (!isUp && attempt < 2) delay(1000)
                    }
                    val latency = if (isUp && successfulLatency > 0) successfulLatency else (System.currentTimeMillis() - start)
                    ServiceStatus(name, url, isUp, if (isUp) latency else 0)
                }
            }.awaitAll()
        }
        
        // Weighted Score Calculation for RU users
        var totalWeightedScore = 0f
        val weights = mapOf(
            "YouTube" to 15,
            "YT Video Stream" to 20,
            "Telegram" to 15,
            "Google" to 10,
            "ChatGPT" to 10,
            "Discord" to 10,
            "GitHub" to 10,
            "Instagram" to 5,
            "X (Twitter)" to 5
        )
        results.forEach { status ->
            val weight = weights[status.name] ?: 0
            if (status.isUp) {
                totalWeightedScore += weight
            }
        }
        
        _connectivityScore.value = totalWeightedScore.toInt().coerceIn(0, 100)
        
        // Track minimum latency of all working bypass channels to estimate current network RTT
        val activeLatencies = results.filter { it.isUp && it.latencyMs > 0 }.map { it.latencyMs }
        if (activeLatencies.isNotEmpty()) {
            val minRtt = activeLatencies.minOrNull() ?: 50L
            BypassConfig.updateRtt(minRtt)
        }

        _statuses.value = results
        _proxyHealth.value = proxyResponsive.get()
        _lastCheckTime.value = System.currentTimeMillis()

        // Autopilot Active Prober: If key services are blocked but we have internet, probe for a working strategy
        val youtubeDown = results.find { it.name == "YouTube" }?.isUp == false
        val streamDown = results.find { it.name == "YT Video Stream" }?.isUp == false
        if (internetUp && (youtubeDown || streamDown || totalWeightedScore < 40f) && BypassConfig.isAutoTuning && !isProbing.get()) {
            val now = System.currentTimeMillis()
            if (now - lastProbeTime > 120000) { // 2 minute cooldown between probes
                lastProbeTime = now
                appContext?.let { runActiveProbing(it) }
            }
        }
    }

    private val _customServices = MutableStateFlow<List<Pair<String, String>>>(emptyList())
    val customServices: StateFlow<List<Pair<String, String>>> = _customServices.asStateFlow()

    fun loadCustomServices(context: android.content.Context) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", android.content.Context.MODE_PRIVATE)
        val saved = prefs.getString("custom_services", "") ?: ""
        if (saved.isNotEmpty()) {
            val list = saved.split(";").mapNotNull {
                val parts = it.split("|")
                if (parts.size == 2) Pair(parts[0], parts[1]) else null
            }
            _customServices.value = list
        } else {
            _customServices.value = emptyList()
        }
    }

    fun addCustomService(context: android.content.Context, name: String, url: String) {
        val current = _customServices.value.toMutableList()
        if (current.none { it.first == name }) {
            current.add(Pair(name, url))
            _customServices.value = current
            saveCustomServices(context, current)
            triggerCheck()
        }
    }

    fun removeCustomService(context: android.content.Context, name: String) {
        val current = _customServices.value.filter { it.first != name }
        _customServices.value = current
        saveCustomServices(context, current)
        triggerCheck()
    }

    private fun saveCustomServices(context: android.content.Context, list: List<Pair<String, String>>) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", android.content.Context.MODE_PRIVATE)
        val serialized = list.joinToString(";") { "${it.first}|${it.second}" }
        prefs.edit().putString("custom_services", serialized).apply()
    }

    fun startChecking(scope: CoroutineScope, context: android.content.Context) {
        if (job?.isActive == true) return
        internalScope = scope
        appContext = context.applicationContext
        loadCustomServices(context)
        
        val defaultServices = listOf(
            Pair("YouTube", "https://www.youtube.com"),
            Pair("YT Video Stream", "https://redirector.googlevideo.com/report_mapping"),
            Pair("Telegram", "https://t.me"),
            Pair("Google", "https://www.google.com"),
            Pair("Instagram", "https://www.instagram.com"),
            Pair("X (Twitter)", "https://x.com"),
            Pair("ChatGPT", "https://chatgpt.com"),
            Pair("Discord", "https://discord.com"),
            Pair("GitHub", "https://github.com"),
            Pair("VK (Control)", "https://vk.com"),
            Pair("Rutube (Control)", "https://rutube.ru"),
            Pair("Yandex (Control)", "https://ya.ru"),
            Pair("Gosuslugi (Control)", "https://www.gosuslugi.ru")
        )
        
        val initialServices = defaultServices + _customServices.value
        _statuses.value = initialServices.map { ServiceStatus(it.first, it.second, false, 0) }

        job = scope.launch(Dispatchers.IO) {
            delay(2000)
            while (isActive) {
                val currentServices = defaultServices + _customServices.value
                checkServices(currentServices)
                
                // Adaptive delay: check faster if key services are down to allow fast healing
                val youtubeDown = _statuses.value.find { it.name == "YouTube" }?.isUp == false
                val streamDown = _statuses.value.find { it.name == "YT Video Stream" }?.isUp == false
                val delayTime = if (youtubeDown || streamDown) 8000L else 30000L // 8s down, 30s up
                // Add minor jitter to avoid synchronized wakeups
                val jitter = (Math.random() * 2000).toLong()
                delay(delayTime + jitter)
            }
        }
    }

    fun stopChecking() {
        job?.cancel()
        job = null
        internalScope = null
        appContext = null
        _statuses.value = emptyList()
    }

    fun runActiveProbing(context: android.content.Context) {
        if (!isProbing.compareAndSet(false, true)) return
        _isProbingState.value = true
        val scope = internalScope ?: CoroutineScope(Dispatchers.IO + SupervisorJob())
        
        ProxyStats.logRecovery("Autopilot: Launching Parallel Strategy Tournament (Fast Race)...")
        
        val testHost = "googlevideo.com"
        
        scope.launch(Dispatchers.IO) {
            val originalStrategy = BypassConfig.strategy.value
            val strategiesToTest = BypassStrategy.entries.filter { it != BypassStrategy.DIRECT }
            
            val resultsChannel = java.util.concurrent.CopyOnWriteArrayList<Pair<BypassStrategy, Long>>()
            val jobs = strategiesToTest.map { strategy ->
                launch {
                    var socket: java.net.Socket? = null
                    try {
                        val start = System.currentTimeMillis()
                        val ips = RobustResolver.resolve(testHost, BypassConfig.activeVpnService)
                        if (ips.isNotEmpty()) {
                            socket = java.net.Socket()
                            BypassConfig.activeVpnService?.protect(socket)
                            socket.soTimeout = 1500
                            withTimeout(3500) {
                                socket.connect(java.net.InetSocketAddress(ips.first(), 443), 1500)
                                val hello = FakePacketHelper.buildFakeClientHello(testHost, (40..90).random())
                                BypassConfig.applyBypass(
                                    socket, 
                                    socket.getOutputStream(), 
                                    hello, 
                                    hello.size, 
                                    BypassConfig.getSessionConfig(testHost, strategy, 100L), 
                                    testHost
                                )
                                socket.getOutputStream().flush()
                                val response = ByteArray(5)
                                if (socket.getInputStream().read(response) >= 1) {
                                    val duration = System.currentTimeMillis() - start
                                    resultsChannel.add(strategy to duration)
                                    BypassConfig.recordStrategyResult(testHost, strategy, true)
                                    BypassConfig.recordSuccess(strategy, duration, context)
                                    ProxyStats.logRecovery("Tournament: ${strategy.name} completed in ${duration}ms")
                                }
                            }
                        }
                    } catch (e: Exception) {
                        BypassConfig.recordStrategyResult(testHost, strategy, false)
                        BypassConfig.recordFailure(strategy, false, context)
                    } finally {
                        try { socket?.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                    }
                }
            }
            
            // Wait for tournament to complete (up to 4.5 seconds maximum)
            withTimeoutOrNull(4500) {
                jobs.forEach { it.join() }
            }
            
            val best = resultsChannel.sortedBy { it.second }.firstOrNull()
            if (best != null) {
                BypassConfig.setStrategy(best.first)
                ProxyStats.logRecovery("Autopilot Tournament Winner -> ${best.first.name} in ${best.second}ms!")
            } else {
                BypassConfig.setStrategy(originalStrategy)
                ProxyStats.logRecovery("Autopilot: No strategy bypassed DPI. Restored ${originalStrategy.name}")
            }
            
            isProbing.set(false)
            _isProbingState.value = false
            triggerCheck()
        }
    }
}
