package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import java.net.InetAddress
import kotlinx.coroutines.*
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.selects.onTimeout
import java.util.concurrent.ConcurrentHashMap

object RobustResolver {
    @Volatile var dnsMode = "Smart DoH"
    @Volatile var customDnsIp = "1.1.1.1"

    private var resolverScope: CoroutineScope? = null
    private val pendingResolutions = ConcurrentHashMap<String, Deferred<List<InetAddress>>>()

    fun initialize(scope: CoroutineScope) {
        resolverScope = scope
    }

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
        val scope = resolverScope ?: GlobalScope
        val deferred = pendingResolutions.computeIfAbsent(cacheKey) {
            scope.async {
                try {
                    performResolution(host, vpnService)
                } finally {
                    pendingResolutions.remove(cacheKey)
                }
            }
        }

        return try {
            withTimeout(12000) {
                deferred.await()
            }
        } catch (e: Exception) {
            pendingResolutions.remove(cacheKey)
            if (e is TimeoutCancellationException) {
                // Return emergency fallback on timeout instead of failing
                DnsCacheManager.getEmergencyFallback(host)?.let { return it }
            }
            throw e
        }
    }

    private suspend fun performResolution(host: String, vpnService: VpnService?): List<InetAddress> {
        val censorship = BypassConfig.censorshipLevel.value
        if (censorship > 50) {
            return performParallelResolution(host, vpnService)
        }
        
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

        // 2. Try Smart Parallel Resolution (DoH, DoT, Shadow UDP)
        try {
            if (ProxyStats.censorshipIntensity.value > 95) {
                val cached = DnsCacheManager.getCached(host) ?: DnsCacheManager.getEmergencyFallback(host)
                if (cached != null) return cached
            }
            
            val par = performParallelResolution(host, vpnService)
            if (par.isNotEmpty()) {
                DnsCacheManager.put(host, par)
                
                // Smart Prefetch common subdomains
                if (!host.startsWith("www.") && host.split(".").size == 2) {
                    CoroutineScope(Dispatchers.IO).launch {
                        listOf("www.", "api.", "assets.", "static.", "m.").forEach { prefix ->
                            try { performParallelResolution(prefix + host, vpnService) } catch (e: Exception) {}
                        }
                    }
                }
                
                return par
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
                val res = DnsProtocols.queryUdpDnsShadow(host, dns, vpnService)
                if (res.isNotEmpty()) {
                    DnsCacheManager.put(host, res)
                    return res
                }
            } catch (e: Exception) {}
        }

        throw java.net.UnknownHostException("Resolution failed for $host")
    }

    private suspend fun performParallelResolution(host: String, vpnService: VpnService?): List<InetAddress> = coroutineScope {
        // Obfuscation: send fake queries for popular domains to hide the real one
        if (ProxyStats.censorshipIntensity.value > 30 && !host.contains("google") && !host.contains("facebook")) {
            launch {
                val shadows = listOf("google.com", "bing.com", "cloudflare.com", "apple.com")
                shadows.shuffled().take(1).forEach { shadow ->
                    try { DnsProtocols.queryUdpDnsShadow(shadow, "1.1.1.1", vpnService) } catch (e: Exception) {}
                }
            }
        }
        
        val jobs = listOf(
            async { DnsProtocols.queryDohRacing(host, vpnService) },
            async { DnsProtocols.queryDot(host, DnsOptimizer.bestDotServer, vpnService) },
            async { DnsProtocols.queryUdpDnsShadow(host, "1.1.1.1", vpnService) },
            async { DnsProtocols.queryUdpDnsShadow(host, "8.8.8.8", vpnService) },
            async { 
                delay(600) // Slight delay for emergency fallback
                DnsCacheManager.getEmergencyFallback(host) ?: emptyList()
            }
        )
        
        val result = select<List<InetAddress>> {
            jobs.forEach { job ->
                job.onAwait { res ->
                    if (res.isNotEmpty()) {
                        jobs.forEach { it.cancel() }
                        res
                    } else {
                        // If empty, we need to wait for others or eventually fail
                        // select will continue waiting if no value is returned
                        // We need a way to know if all failed.
                        // For simplicity, we just return the first non-empty or throw below.
                        emptyList<InetAddress>() 
                    }
                }
            }
            // Timeout if none respond in 5s
            onTimeout(5000L) { emptyList<InetAddress>() }
        }
        
        if (result.isNotEmpty()) {
            DnsCacheManager.put(host, result)
            return@coroutineScope result
        }
        
        // Final fallback: wait for any success or throw
        val any = jobs.awaitAll().flatten().distinct()
        if (any.isNotEmpty()) {
            DnsCacheManager.put(host, any)
            return@coroutineScope any
        }
        
        throw java.net.UnknownHostException("Parallel resolution failed for $host")
    }

    fun startDnsOptimizer(scope: CoroutineScope, vpnService: VpnService?) {
        DnsOptimizer.start(scope, vpnService)
    }

    fun stopBackgroundProber() {
        // Handled by scope cancellation in Service
    }
}
