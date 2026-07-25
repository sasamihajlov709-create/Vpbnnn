package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import java.net.InetAddress
import kotlinx.coroutines.*
import java.util.concurrent.ConcurrentHashMap

object RobustResolver {
    @Volatile var dnsMode = "Smart DoH"
    @Volatile var customDnsIp = "1.1.1.1"

    private val resolverScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val pendingResolutions = ConcurrentHashMap<String, Deferred<List<InetAddress>>>()

    fun loadDnsSettings(context: android.content.Context) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", android.content.Context.MODE_PRIVATE)
        dnsMode = prefs.getString("dns_mode", "Smart DoH") ?: "Smart DoH"
        customDnsIp = prefs.getString("custom_dns_ip", "1.1.1.1") ?: "1.1.1.1"
    }

    fun saveDnsSettings(context: android.content.Context, mode: String, ip: String) {
        dnsMode = mode
        customDnsIp = ip
        context.getSharedPreferences("pink_proxy_settings", android.content.Context.MODE_PRIVATE).edit()
            .putString("dns_mode", mode)
            .putString("custom_dns_ip", ip)
            .apply()
        DnsCacheManager.clear()
    }

    fun getCached(host: String): List<InetAddress>? = DnsCacheManager.getCached(host)

    fun clearCache() = DnsCacheManager.clear()

    suspend fun resolve(host: String, vpnService: VpnService? = null): List<InetAddress> {
        if (DnsCacheManager.isIpAddress(host)) {
            return try { listOf(InetAddress.getByName(host)) } catch (e: Exception) { emptyList() }
        }

        val cached = DnsCacheManager.getCached(host)
        if (cached != null) return cached

        val cacheKey = host.lowercase()
        val deferred = pendingResolutions.computeIfAbsent(cacheKey) {
            resolverScope.async {
                try {
                    performResolution(host, vpnService)
                } finally {
                    pendingResolutions.remove(cacheKey)
                }
            }
        }

        return try {
            withTimeout(10000) {
                deferred.await()
            }
        } catch (e: Exception) {
            pendingResolutions.remove(cacheKey)
            throw e
        }
    }

    private suspend fun performResolution(host: String, vpnService: VpnService?): List<InetAddress> {
        val isCensored = BypassConfig.isHostCensored(host)
        val isDirect = BypassConfig.isHostDirect(host)

        // 1. Try Direct if not censored
        if (isDirect && !isCensored) {
            try {
                val res = InetAddress.getAllByName(host).toList()
                if (res.isNotEmpty() && !DnsCacheManager.isPoisoned(res.first(), host)) {
                    DnsCacheManager.put(host, res)
                    return res
                }
            } catch (e: Exception) {}
        }

        // 2. Try Smart DoH / Racing
        try {
            val racing = DnsProtocols.queryDohRacing(host, vpnService)
            if (racing.isNotEmpty()) {
                DnsCacheManager.put(host, racing)
                return racing
            }
        } catch (e: Exception) {}

        // 3. Emergency Fallback
        DnsCacheManager.getEmergencyFallback(host)?.let {
            DnsCacheManager.put(host, it)
            return it
        }

        // 4. UDP/TCP Fallbacks
        val servers = if (dnsMode == "Custom") listOf(customDnsIp) else listOf("8.8.8.8", "1.1.1.1", "9.9.9.9")
        for (dns in servers) {
            try {
                val res = DnsProtocols.queryUdpDns(host, dns, vpnService)
                if (res.isNotEmpty()) {
                    DnsCacheManager.put(host, res)
                    return res
                }
            } catch (e: Exception) {}
        }

        throw java.net.UnknownHostException("Resolution failed for $host")
    }

    fun startDnsOptimizer(scope: CoroutineScope, vpnService: VpnService?) {
        DnsOptimizer.start(scope, vpnService)
    }

    fun stopBackgroundProber() {
        // Handled by scope cancellation in Service
    }
}
