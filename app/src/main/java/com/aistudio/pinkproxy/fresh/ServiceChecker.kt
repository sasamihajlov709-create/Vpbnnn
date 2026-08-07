package com.aistudio.pinkproxy.fresh

import android.content.Context
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.atomic.AtomicBoolean

object ServiceChecker {
    var proxyPort = 18080
    data class ServiceStatus(val name: String, val url: String, val isUp: Boolean, val latencyMs: Long)

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

    private val _isProbingState = MutableStateFlow(false)
    val isProbingState: StateFlow<Boolean> = _isProbingState.asStateFlow()

    private var job: Job? = null
    private var internalScope: CoroutineScope? = null
    private val isProbing = AtomicBoolean(false)
    var appContext: Context? = null
    
    val customServices = PinkServiceStatusManager.customServices

    fun loadCustomServices(context: Context) = PinkServiceStatusManager.loadCustomServices(context)
    fun addCustomService(context: Context, name: String, url: String) = PinkServiceStatusManager.addCustomService(context, name, url)
    fun removeCustomService(context: Context, name: String) = PinkServiceStatusManager.removeCustomService(context, name)
    
    fun triggerCheck() {
        val scope = internalScope ?: return
        val services = _statuses.value.map { it.name to it.url }
        if (services.isNotEmpty()) {
            scope.launch { checkServices(services) }
        }
    }

    private suspend fun checkServices(servicesToCheck: List<Pair<String, String>>) {
        if (!isProbing.compareAndSet(false, true)) return
        _isProbingState.value = true
        try {
            val finalInternet = NetworkProber.checkBaselineInternet(appContext)
            _internetAvailable.value = finalInternet

            val relayResponsive = NetworkProber.checkProxyReachable(proxyPort)
            _proxyHealth.value = relayResponsive
            
            if (!relayResponsive && finalInternet) {
                RecoveryManager.handleEvent(RecoveryEvent.PROXY_UNREACHABLE, "Local proxy port $proxyPort unresponsive")
            }

            val results = coroutineScope {
                servicesToCheck.map { (name, url) ->
                    async { NetworkProber.probeServiceViaProxy(name, url, proxyPort) }
                }.awaitAll()
            }
            
            calculateScores(results)
            
            _statuses.value = results
            _proxyHealth.value = results.any { it.isUp } || relayResponsive
            _lastCheckTime.value = System.currentTimeMillis()
            
            handlePanicLogic(results, finalInternet)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e("ServiceChecker", "Check failed: ${e.message}")
        } catch (e: Throwable) {
            Log.e("ServiceChecker", "Critical checker error", e)
        } finally {
            isProbing.set(false)
            _isProbingState.value = false
        }
    }

    private fun calculateScores(results: List<ServiceStatus>) {
        var totalWeightedScore = 0f
        var controlUp = 0
        var censoredDown = 0
        
        val weights = mapOf(
            "YouTube" to 15, "YT Video Stream" to 20, "Telegram" to 15,
            "Google" to 10, "ChatGPT" to 10, "Discord" to 10,
            "GitHub" to 10, "Instagram" to 5, "X (Twitter)" to 5
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
        
        if (controlUp >= 2 && censoredDown >= 1) {
            val newIntensity = (censoredDown * 30).coerceIn(0, 100)
            if (newIntensity > ProxyStats.censorshipIntensity.value) {
                ProxyStats.updateCensorshipIntensity(newIntensity)
            }
        }
        
        _connectivityScore.value = totalWeightedScore.toInt().coerceIn(0, 100)
        
        val activeLatencies = results.filter { it.isUp && it.latencyMs > 0 }.map { it.latencyMs }
        if (activeLatencies.isNotEmpty()) {
            TrafficShaper.updateRtt(activeLatencies.minOrNull() ?: 50L)
        }
    }

    private fun handlePanicLogic(results: List<ServiceStatus>, finalInternet: Boolean) {
        val anyServiceUp = results.any { it.isUp }
        if (!anyServiceUp && finalInternet && results.isNotEmpty()) {
            if (!BypassConfig.isPanicModeFlow.value) {
                BypassConfig.setPanicMode(true)
                ProxyStats.logRecovery("CRITICAL: All proxied services unreachable. Panic Mode active.")
            }
        } else if (anyServiceUp && BypassConfig.isPanicModeFlow.value && results.count { it.isUp } >= 2) {
            if (ProxyStats.successRate.value > 80) {
                 BypassConfig.setPanicMode(false)
                 ProxyStats.logRecovery("Recovery detected: Disabling Panic Mode.")
            }
        }
    }

    fun startChecking(scope: CoroutineScope, context: Context) {
        if (job?.isActive == true) return
        internalScope = scope
        appContext = context.applicationContext
        PinkServiceStatusManager.loadCustomServices(context)
        
        job = scope.launch {
            while (isActive) {
                val services = PinkServiceStatusManager.getDefaultServices() + PinkServiceStatusManager.customServices.value
                checkServices(services)
                delay(300000L) // 5 minutes
            }
        }
    }

    fun runActiveProbing(context: Context) {
        val scope = internalScope ?: return
        scope.launch {
            val services = PinkServiceStatusManager.getDefaultServices() + PinkServiceStatusManager.customServices.value
            checkServices(services)
        }
    }

    fun stopChecking() {
        job?.cancel()
        job = null
    }
}
