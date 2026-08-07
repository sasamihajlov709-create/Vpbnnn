package com.aistudio.pinkproxy.fresh

import android.content.Context
import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import kotlin.coroutines.coroutineContext
import java.net.InetAddress
import java.net.Socket
import java.net.InetSocketAddress

object PrefetchManager {
    private val scope = CoroutineScope(ProxyDispatcher.io + SupervisorJob() + ProxyDispatcher.globalHandler)
    private var prefetchJob: Job? = null

    private val topDomains = listOf(
        "google.com", "dns.google", "cloudflare.com", "telegram.org", "github.com",
        "youtube.com", "googlevideo.com", "openai.com", "chatgpt.com", "bing.com",
        "facebook.com", "instagram.com", "twitter.com", "x.com", "discord.com"
    )

    fun start(context: Context, vpnService: VpnService?) {
        prefetchJob?.cancel()
        prefetchJob = scope.launch {
            while (isActive) {
                try {
                    // Ждем благоприятных условий
                    val delayMs = if (BypassConfig.isCharging || (BypassConfig.batteryLevel > 80 && !BypassConfig.isPowerSaveMode)) {
                        if (BypassConfig.currentNetworkType.value == NetworkType.WIFI) 300000L else 600000L
                    } else {
                        1200000L // 20 минут если батарея низкая
                    }
                    delay(delayMs)

                    if (!BypassConfig.isDiagnosticMode) {
                        performPrefetch(vpnService)
                    }
                } catch (e: CancellationException) {
                    break
                } catch (e: Throwable) {
                    Log.e("PrefetchManager", "Prefetch error", e)
                    delay(60000)
                }
            }
        }
    }

    private suspend fun performPrefetch(vpnService: VpnService?) {
        Log.i("PrefetchManager", "Starting proactive prefetch for ${topDomains.size} domains")
        
        topDomains.shuffled().forEach { host ->
            if (!coroutineContext.isActive) return@forEach
            
            // 1. DNS Prefetch
            val ips = RobustResolver.resolve(host, vpnService)
            if (ips.isNotEmpty()) {
                // 2. TCP Warming (только если мы на зарядке или WiFi)
                if (BypassConfig.isCharging || BypassConfig.currentNetworkType.value == NetworkType.WIFI) {
                    warmupConnection(host, ips, vpnService)
                }
            }
            delay(2000) // Пауза между доменами
        }
    }

    private suspend fun warmupConnection(host: String, ips: List<InetAddress>, vpnService: VpnService?) {
        val strat = BypassConfig.getBestStrategyForHost(host)
        if (strat.group == StrategyGroup.LIGHT || strat.group == StrategyGroup.MEDIUM) {
            withContext(ProxyDispatcher.io) {
                val s = Socket()
                try {
                    vpnService?.protect(s)
                    TtlHelper.tuneSocket(s)
                    TtlHelper.applyMssClamping(s, host)
                    // Пытаемся просто открыть соединение на 443 порт
                    s.connect(InetSocketAddress(ips.first(), 443), 3000)
                    // Если успешно, сразу закрываем. Это "прогревает" маршруты и кэши в сети оператора.
                    Log.d("PrefetchManager", "Warmed up connection to $host")
                } catch (e: Throwable) {
                } finally {
                    try { s.close() } catch (e: Throwable) {}
                }
            }
        }
    }

    fun stop() {
        prefetchJob?.cancel()
    }
}
