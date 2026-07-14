package com.example

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.net.HttpURLConnection
import java.net.URL
import java.net.Proxy
import java.net.InetSocketAddress

object ServiceChecker {
    var proxyPort = 8080
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
    
    fun triggerCheck() {
        val scope = internalScope ?: return
        val services = _statuses.value.map { it.name to it.url }
        if (services.isNotEmpty()) {
            scope.launch { checkServices(services) }
        }
    }

    private suspend fun checkServices(servicesToCheck: List<Pair<String, String>>) {
        var proxyResponsive = true
        var internetUp = false

        // Baseline check: multiple reliable domains (without proxy)
        val baselineDomains = listOf("https://ya.ru", "https://www.google.com/generate_204", "https://www.apple.com/library/test/success.html")
        for (domain in baselineDomains) {
            try {
                val conn = URL(domain).openConnection(java.net.Proxy.NO_PROXY) as HttpURLConnection
                conn.connectTimeout = 3000
                conn.readTimeout = 3000
                conn.requestMethod = "GET"
                if (conn.responseCode in 200..499) {
                    internetUp = true
                    conn.disconnect()
                    break
                }
                conn.disconnect()
            } catch (e: Exception) {}
        }
        _internetAvailable.value = internetUp

        val results = servicesToCheck.map { (name, url) ->
            coroutineScope {
                async {
                    val start = System.currentTimeMillis()
                    var isUp = false
                    var attempt = 0
                    while (attempt < 2 && !isUp) {
                        try {
                            val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", proxyPort))
                            val connection = URL(url).openConnection(proxy) as HttpURLConnection
                            connection.connectTimeout = 8000
                            connection.readTimeout = 8000
                            connection.instanceFollowRedirects = true
                            connection.requestMethod = "HEAD"
                            connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                            
                            val code = connection.responseCode
                            isUp = (code in 200..499)
                            
                            // Throttling detection: if latency > 6s for critical services, consider it "down"
                            val latencyThreshold = if (name.contains("Stream")) 4000 else 6000
                            if (isUp && (name.contains("YouTube") || name.contains("Telegram")) && System.currentTimeMillis() - start > latencyThreshold) {
                                isUp = false 
                            }
                            
                            connection.disconnect()
                        } catch (e: Exception) {
                            isUp = false
                            if (e is java.net.ConnectException && e.message?.contains("127.0.0.1") == true) {
                                proxyResponsive = false
                            }
                            if (!isUp) {
                                attempt++
                                if (attempt < 2) delay(1000)
                            }
                        }
                    }
                    val latency = System.currentTimeMillis() - start
                    ServiceStatus(name, url, isUp, if (isUp) latency else 0)
                }
            }
        }.awaitAll()
        
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
        
        _statuses.value = results
        _proxyHealth.value = proxyResponsive
        _lastCheckTime.value = System.currentTimeMillis()
    }

    fun startChecking(scope: CoroutineScope) {
        if (job?.isActive == true) return
        internalScope = scope
        val servicesToCheck = listOf(
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
        
        _statuses.value = servicesToCheck.map { ServiceStatus(it.first, it.second, false, 0) }

        job = scope.launch(Dispatchers.IO) {
            delay(2000)
            while (isActive) {
                checkServices(servicesToCheck)
                
                // Adaptive delay: check faster if key services are down
                val youtubeDown = _statuses.value.find { it.name == "YouTube" }?.isUp == false
                val delayTime = if (youtubeDown) 30000L else 60000L
                delay(delayTime)
            }
        }
    }

    fun stopChecking() {
        job?.cancel()
        job = null
        _statuses.value = emptyList()
    }
}
