package com.aistudio.pinkproxy.fresh

import android.util.Log
import kotlinx.coroutines.*
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger

object DiagnosticManager {
    private val scope = CoroutineScope(ProxyDispatcher.io + SupervisorJob())
    
    data class HealthStatus(
        val dnsOk: Boolean,
        val tcpOk: Boolean,
        val censorshipIntensity: Int,
        val bestStrategy: String,
        val recommendation: String
    )

    suspend fun runFullDiagnostic(): HealthStatus = withContext(ProxyDispatcher.io) {
        val dnsSuccess = AtomicInteger(0)
        val tcpSuccess = AtomicInteger(0)
        
        val testDomains = listOf("google.com", "telegram.org", "github.com")
        
        // 1. Проверка DNS
        val dnsJobs = testDomains.map { domain ->
            launch {
                val ips = RobustResolver.resolve(domain, BypassConfig.activeVpnService)
                if (ips.isNotEmpty()) dnsSuccess.incrementAndGet()
            }
        }
        
        // 2. Проверка TCP
        val tcpJobs = testDomains.map { domain ->
            launch {
                val ips = RobustResolver.resolve(domain, BypassConfig.activeVpnService)
                if (ips.isNotEmpty()) {
                    val socket = Socket()
                    try {
                        BypassConfig.activeVpnService?.protect(socket)
                        socket.connect(InetSocketAddress(ips.first(), 443), 3000)
                        tcpSuccess.incrementAndGet()
                    } catch (e: Throwable) {
                    } finally {
                        try { socket.close() } catch (e: Throwable) {}
                    }
                }
            }
        }
        
        (dnsJobs + tcpJobs).joinAll()
        
        val intensity = ProxyStats.censorshipIntensity.value
        val bestStrat = BypassStrategy.SNI_SPLIT.name
        
        val rec = when {
            tcpSuccess.get() == 0 -> "Критическая блокировка TCP. Попробуйте сменить сеть или включить режим 'Extreme'."
            dnsSuccess.get() < 2 -> "DNS отравлен или заблокирован. Рекомендуется DoH Extreme."
            intensity > 80 -> "Высокая цензура. Используется фрагментация пакетов."
            else -> "Соединение стабильно."
        }
        
        HealthStatus(
            dnsOk = dnsSuccess.get() > 0,
            tcpOk = tcpSuccess.get() > 0,
            censorshipIntensity = intensity,
            bestStrategy = bestStrat,
            recommendation = rec
        )
    }

    fun logDiagnostic(tag: String, message: String) {
        if (BypassConfig.isDiagnosticMode) {
            Log.i("DIAG_$tag", message)
            ProxyStats.logRecovery("DIAG: $message")
        }
    }
}
