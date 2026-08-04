package com.aistudio.pinkproxy.fresh

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.content.Context
import android.util.Log
import androidx.core.content.edit
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





    private var job: Job? = null
    private var internalScope: CoroutineScope? = null
    private val _isProbingState = MutableStateFlow(false)
    val isProbingState: StateFlow<Boolean> = _isProbingState.asStateFlow()
    private val isProbing = java.util.concurrent.atomic.AtomicBoolean(false)
    private var lastProbeTime = 0L
    var appContext: android.content.Context? = null
    
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

        // Baseline check 1: System ConnectivityManager
        val cm = appContext?.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val activeNetwork = cm?.activeNetwork
        val capabilities = cm?.getNetworkCapabilities(activeNetwork)
        val systemInternet = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true &&
                            capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
        
        // Baseline check 2: Manual Probing (trust this more for bypass scenarios)
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
                    break
                }
            } catch (e: Throwable) { android.util.Log.v("PinkProxy", "Baseline ignored: ${e.message}") } finally {
                try { conn?.disconnect() } catch (e: Throwable) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
            }
        }
        
        // Final Internet status: either system says yes, or our prober says yes
        val finalInternet = internetUp || systemInternet
        _internetAvailable.value = finalInternet

        // Deep Proxy Integrity Check
        val relayResponsive = try {
            val sock = java.net.Socket()
            sock.connect(java.net.InetSocketAddress("127.0.0.1", proxyPort), 1000)
            sock.close()
            true
        } catch (e: Throwable) {
            false
        }
        _proxyHealth.value = relayResponsive
        
        if (!relayResponsive && finalInternet) {
            RecoveryManager.handleEvent(RecoveryEvent.PROXY_UNREACHABLE, "Local proxy port $proxyPort unresponsive during check")
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
                            val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", proxyPort))
                            connection = URL(url).openConnection(proxy) as HttpURLConnection
                            connection.connectTimeout = 5000
                            connection.readTimeout = 5000
                            connection.instanceFollowRedirects = true
                            connection.requestMethod = "HEAD"
                            connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                            
                            var code = connection.responseCode
                            if (code == 405) { // Method Not Allowed for HEAD, fallback to quick GET without reading body
                                connection.disconnect()
                                connection = URL(url).openConnection(proxy) as HttpURLConnection
                                connection.connectTimeout = 5000
                                connection.readTimeout = 5000
                                connection.instanceFollowRedirects = true
                                connection.requestMethod = "GET"
                                connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                                code = connection.responseCode
                            }
                            isUp = (code in 200..399)
                            
                            val attemptDuration = System.currentTimeMillis() - attemptStart
                            if (isUp) {
                                successfulLatency = attemptDuration
                            }
                            
                            // Throttling detection: if latency > 6s for critical services, consider it "down"
                            val latencyThreshold = if (name.contains("Stream")) 4500 else 7000
                            if (isUp && (name.contains("YouTube") || name.contains("Telegram")) && attemptDuration > latencyThreshold) {
                                isUp = false 
                            }
                        } catch (e: Throwable) {
                            isUp = false
                            if (e is java.net.ConnectException || e.message?.contains("127.0.0.1") == true || e.message?.contains("refused") == true) {
                                proxyResponsive.set(false)
                            }
                        } finally {
                            try { connection?.inputStream?.close() } catch (e: Throwable) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                            try { connection?.errorStream?.close() } catch (e: Throwable) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                            try { connection?.disconnect() } catch (e: Throwable) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
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
        var controlUp = 0
        var censoredDown = 0
        
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
                if (status.name.contains("(Control)")) controlUp++
            } else {
                if (status.name == "YouTube" || status.name == "Telegram" || status.name == "Instagram") censoredDown++
            }
        }
        
        // Intelligent Censorship Intensity logic
        if (controlUp >= 2 && censoredDown >= 1) {
            val newIntensity = (censoredDown * 30).coerceIn(0, 100)
            if (newIntensity > ProxyStats.censorshipIntensity.value) {
                ProxyStats.updateCensorshipIntensity(newIntensity)
            }
        }
        
        _connectivityScore.value = totalWeightedScore.toInt().coerceIn(0, 100)
        
        // Track minimum latency
        val activeLatencies = results.filter { it.isUp && it.latencyMs > 0 }.map { it.latencyMs }
        if (activeLatencies.isNotEmpty()) {
            val minRtt = activeLatencies.minOrNull() ?: 50L
            BypassConfig.TrafficShaper.updateRtt(minRtt)
        }

        _statuses.value = results
        
        // Re-evaluate internet availability: if any service is reachable via proxy, the internet is up!
        val anyServiceUp = results.any { it.isUp }
        if (anyServiceUp) {
            internetUp = true
            _internetAvailable.value = true
        }
        
        _proxyHealth.value = proxyResponsive.get()
        _lastCheckTime.value = System.currentTimeMillis()
        
        // Auto-Panic Logic: If internet is baseline ok but nothing is reachable via proxy
        if (!anyServiceUp && finalInternet && results.isNotEmpty()) {
            if (!BypassConfig.isPanicModeFlow.value) {
                BypassConfig.setPanicMode(true)
                ProxyStats.logRecovery("CRITICAL: All proxied services unreachable. Emergency Panic Mode activated.")
            }
        } else if (anyServiceUp && BypassConfig.isPanicModeFlow.value && results.count { it.isUp } >= 2) {
            // Self-healing: if services are recovering, consider leaving panic mode
            if (ProxyStats.successRate.value > 80) {
                 BypassConfig.setPanicMode(false)
                 ProxyStats.logRecovery("Recovery detected: Disabling Panic Mode.")
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
        prefs.edit { putString("custom_services", serialized) }
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

        job = scope.launch(ProxyDispatcher.io) {
            delay(2000)
            while (isActive) {
                try {
                    val currentServices = defaultServices + _customServices.value
                    checkServices(currentServices)
                    
                    // Interval: 20 minutes in background to conserve battery and data
                    val delayTime = 1200000L
                    val jitter = (java.util.concurrent.ThreadLocalRandom.current().nextDouble() * 5000).toLong()
                    delay(delayTime + jitter)
                } catch (e: kotlinx.coroutines.CancellationException) {
                    throw e
                } catch (e: Throwable) {
                    android.util.Log.e("ServiceChecker", "Checker error", e)
                }
            }
        }
    }

    suspend fun probeHostWithStrategy(host: String, strategy: BypassStrategy): Boolean {
        return withContext(ProxyDispatcher.io) {
            var socket: java.net.Socket? = null
            try {
                val ips = RobustResolver.resolve(host, BypassConfig.activeVpnService)
                if (ips.isEmpty()) return@withContext false
                
                socket = java.net.Socket()
                try { BypassConfig.activeVpnService?.protect(socket) } catch(e: Throwable) {}
                socket.soTimeout = 2000
                withTimeout(4000) {
                    socket.connect(java.net.InetSocketAddress(ips.first(), 443), 2000)
                    val hello = FakePacketHelper.buildFakeClientHello(host, java.util.concurrent.ThreadLocalRandom.current().nextInt(40, 91))
                    BypassConfig.applyBypass(
                        socket, 
                        socket.getOutputStream(), 
                        hello, 
                        hello.size, 
                        BypassConfig.getSessionConfig(host, strategy, 100L), 
                        host
                    )
                    socket.getOutputStream().flush()
                    val response = ByteArray(5)
                    socket.getInputStream().read(response) >= 1
                }
            } catch (e: Throwable) {
                false
            } finally {
                try { socket?.close() } catch (e: Throwable) { android.util.Log.v("ServiceChecker", "Ignored: ${e.message}") }
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

    fun runActiveProbing(context: android.content.Context?) {
        val actualContext = context ?: appContext ?: return
        if (!isProbing.compareAndSet(false, true)) return
        _isProbingState.value = true
        val currentScope = internalScope
        val scope = if (currentScope?.isActive == true) currentScope else CoroutineScope(ProxyDispatcher.io + SupervisorJob() + ProxyDispatcher.globalHandler)
        
        ProxyStats.logRecovery("Autopilot: Launching Parallel Strategy Tournament (Advanced Race)...")
        
        val testHosts = listOf("googlevideo.com", "api.telegram.org", "discord.com", "instagram.com")
        
        scope.launch(ProxyDispatcher.io) {
            try {
                _isProbingState.value = true
                val originalStrategy = BypassConfig.strategy.value
                val currentCensorship = ProxyStats.censorshipIntensity.value
                
                // Only test heavy strategies if censorship is high
                val strategiesToTest = BypassStrategy.entries.filter { 
                    it != BypassStrategy.DIRECT && 
                    (it.family == StrategyFamily.TLS || it.family == StrategyFamily.TCP || it.family == StrategyFamily.UDP || it.family == StrategyFamily.ADAPTIVE || it.family == StrategyFamily.FRAGMENTATION || it.family == StrategyFamily.TIMING) &&
                    (if (currentCensorship < 30) it.group != StrategyGroup.EXTREME else true)
                }.shuffled().take(8)
                
                BypassConfig.updateTestingStrategies(strategiesToTest)
                
                val resultsChannel = java.util.concurrent.CopyOnWriteArrayList<Triple<BypassStrategy, Long, Int>>() // Strategy, Duration, SuccessCount
                
                // Group strategies to avoid overwhelming the system with concurrent DNS/Socket calls
                val chunks = strategiesToTest.chunked(2) 
                
                for (chunk in chunks) {
                    val chunkJobs = chunk.map { strategy ->
                        launch {
                            var successCount = 0
                            var totalDuration = 0L
                            
                            for (host in testHosts) {
                                if (!isActive) break
                                var success = false
                                val start = System.currentTimeMillis()
                                
                                val vpn = BypassConfig.activeVpnService
                                if (vpn == null) {
                                    ProxyStats.logRecovery("Probing: VPN service lost, aborting chunk.")
                                    return@launch
                                }

                                try {
                                    if (strategy.family == StrategyFamily.UDP) {
                                        // Test UDP strategy using a DNS query as a proxy for UDP connectivity
                                        val res = DnsProtocols.queryUdpDnsShadow(host, "8.8.8.8", vpn)
                                        if (res.isNotEmpty()) {
                                            success = true
                                        }
                                    } else {
                                        var socket: java.net.Socket? = null
                                        try {
                                            val ips = RobustResolver.resolve(host, vpn)
                                            if (ips.isNotEmpty()) {
                                                socket = java.net.Socket()
                                                try { vpn.protect(socket) } catch(e: Throwable) {}
                                                socket.soTimeout = 1500
                                                withTimeout(3000) {
                                                    socket.connect(java.net.InetSocketAddress(ips.first(), 443), 1500)
                                                    val hello = FakePacketHelper.buildFakeClientHello(host, java.util.concurrent.ThreadLocalRandom.current().nextInt(50, 95))
                                                    
                                                    val out = socket.getOutputStream()
                                                    if (out != null) {
                                                        BypassConfig.applyBypass(
                                                            socket, 
                                                            out, 
                                                            hello, 
                                                            hello.size, 
                                                            BypassConfig.getSessionConfig(host, strategy, 150L), 
                                                            host
                                                        )
                                                        out.flush()
                                                        
                                                        val input = socket.getInputStream()
                                                        if (input != null) {
                                                            val response = ByteArray(5)
                                                            val readCount = input.read(response)
                                                            if (readCount >= 1 && (response[0] == 0x16.toByte() || response[0] == 0x17.toByte() || response[0] == 0x14.toByte() || response[0] == 'H'.code.toByte())) {
                                                                success = true
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        } catch (e: Throwable) {
                                            // Ignore probe failures
                                        } finally {
                                            try { socket?.close() } catch (e: Throwable) {}
                                        }
                                    }
                                } catch (e: Throwable) {
                                    if (e is CancellationException) throw e
                                }
                                
                                if (success) {
                                    successCount++
                                    totalDuration += (System.currentTimeMillis() - start)
                                }
                                BypassConfig.recordStrategyResult(host, strategy, success)
                            }
                            
                            if (successCount > 0) {
                                val avgDuration = totalDuration / successCount
                                resultsChannel.add(Triple(strategy, avgDuration, successCount))
                                ProxyStats.logRecovery("Tournament: ${strategy.name} scored $successCount/${testHosts.size} (avg ${avgDuration}ms)")
                            }
                        }
                    }
                    chunkJobs.forEach { it.join() }
                    if (!isActive) break
                }
                
                val best = resultsChannel
                    .sortedWith(compareByDescending<Triple<BypassStrategy, Long, Int>> { it.third }.thenBy { it.second })
                    .firstOrNull()
                    
                if (best != null && best.third > 0) {
                    // Do not hardcode the global strategy based on a single background smoke test.
                    // Just let the optimizer know this strategy had a successful probe.
                    BypassConfig.recordStrategyResult("global_probe", best.first, true, best.second)
                    ProxyStats.logRecovery("Autopilot Tournament Winner -> ${best.first.name} (${best.third}/${testHosts.size} hosts ok)! Logged for ranking.")
                    
                    // If the winner is very stable, maybe reduce intensity slightly
                    if (best.third == testHosts.size && best.second < 400) {
                        ProxyStats.updateCensorshipIntensity((ProxyStats.censorshipIntensity.value - 5).coerceAtLeast(0))
                    }
                } else {
                    ProxyStats.logRecovery("CRITICAL: Autopilot failed to find a working strategy in tournament!")
                    ProxyStats.updateCensorshipIntensity((ProxyStats.censorshipIntensity.value + 15).coerceAtMost(100))
                    BypassConfig.setPanicMode(true)
                }
            } catch (e: Throwable) {
                if (e is CancellationException) throw e
                Log.e("ServiceChecker", "Error during active probing tournament", e)
            } finally {
                isProbing.set(false)
                _isProbingState.value = false
                triggerCheck()
            }
        }
    }

    suspend fun probeBestMtu(host: String): Int {
        val sizes = listOf(1460, 1400, 1300, 1200, 1100, 1000, 800, 512)
        for (size in sizes) {
            if (probeHostWithPacketSize(host, size)) return size
        }
        return 512
    }

    private suspend fun probeHostWithPacketSize(host: String, size: Int): Boolean {
        var socket: java.net.Socket? = null
        try {
            val ips = RobustResolver.resolve(host, BypassConfig.activeVpnService)
            if (ips.isEmpty()) return false
            
            socket = java.net.Socket()
            try { BypassConfig.activeVpnService?.protect(socket) } catch(e: Throwable) {}
            socket.soTimeout = 2000
            return withTimeout(3000) {
                socket.connect(java.net.InetSocketAddress(ips.first(), 443), 2000)
                val baseHello = FakePacketHelper.buildFakeClientHello(host, 32)
                val paddingNeeded = (size - baseHello.size - 5).coerceAtLeast(0)
                val paddedHello = if (paddingNeeded > 0) {
                    FakePacketHelper.injectTlsPadding(baseHello, baseHello.size, paddingNeeded)
                } else baseHello
                
                socket.getOutputStream().write(paddedHello)
                socket.getOutputStream().flush()
                
                val response = ByteArray(5)
                val readCount = socket.getInputStream().read(response)
                readCount >= 1 && response[0] == 0x16.toByte()
            }
        } catch (e: Throwable) {
            return false
        } finally {
            try { socket?.close() } catch (e: Throwable) {}
        }
    }
}
