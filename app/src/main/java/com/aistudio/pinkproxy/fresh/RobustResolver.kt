package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import java.net.InetAddress
import androidx.core.content.edit
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

    @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
    private fun getScope(): CoroutineScope = resolverScope ?: GlobalScope

    fun loadDnsSettings(context: android.content.Context) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", android.content.Context.MODE_PRIVATE)
        dnsMode = prefs.getString("dns_mode", "Smart DoH") ?: "Smart DoH"
        customDnsIp = prefs.getString("custom_dns_ip", "1.1.1.1") ?: "1.1.1.1"
    }

    fun saveDnsSettings(context: android.content.Context, mode: String, ip: String) {
        dnsMode = mode
        customDnsIp = ip
        context.getSharedPreferences("pink_proxy_settings", android.content.Context.MODE_PRIVATE).edit {
            putString("dns_mode", mode)
            putString("custom_dns_ip", ip)
        }
        DnsCacheManager.clear()
    }

    fun getCached(host: String): List<InetAddress>? = DnsCacheManager.getCached(host)

    fun clearCache() = DnsCacheManager.clear()

    @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
    suspend fun resolve(host: String, vpnService: VpnService? = null): List<InetAddress> {
        if (DnsCacheManager.isIpAddress(host)) {
            return try { listOf(InetAddress.getByName(host)) } catch (e: Throwable) { emptyList() }
        }
        if (DnsCacheManager.isNegative(host)) return emptyList()

        val cached = DnsCacheManager.getCached(host)
        if (cached != null) return cached

        val cacheKey = host.lowercase()
        val scope = getScope()
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
        } catch (e: Throwable) {
            if (e is CancellationException) throw e
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
                val res = DnsProtocols.queryUdpDnsShadow(host, "8.8.8.8", vpnService)
                if (res.isNotEmpty() && !DnsCacheManager.isPoisoned(res.first(), host)) {
                    DnsCacheManager.put(host, res)
                    return res
                }
            } catch (e: Throwable) {
                if (e is CancellationException) throw e
            }
        }

        // 2. Try Smart Parallel Resolution (DoH, DoT, Shadow UDP)
        try {
            if (ProxyStats.censorshipIntensity.value > 95) {
                val cached = DnsCacheManager.getCached(host) ?: DnsCacheManager.getEmergencyFallback(host)
                if (cached != null) return cached
            }
            
            val par = performParallelResolution(host, vpnService)
            if (par.isNotEmpty()) {
                if (DnsCacheManager.isSuspicious(host, par)) {
                    ProxyStats.recordDpiEvent(DpiType.DNS_POISONING)
                } else {
                    val sorted = DnsCacheManager.getSortedIps(par)
                    DnsCacheManager.put(host, sorted)
                    
                    // Smart Prefetch common subdomains
                    if (!host.startsWith("www.") && host.split(".").size == 2) {
                        getScope().launch {
                            listOf("www.", "api.", "assets.", "static.", "m.").forEach { prefix ->
                                try { 
                                    val preHost = prefix + host
                                    if (DnsCacheManager.getCached(preHost) == null) {
                                        performParallelResolution(preHost, vpnService) 
                                    }
                                } catch (e: Throwable) { 
                                    if (e is CancellationException) throw e 
                                }
                            }
                        }
                    }
                    return sorted
                }
            }
        } catch (e: Throwable) {
            if (e is CancellationException) throw e
        }

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
            } catch (e: Throwable) {
                if (e is CancellationException) throw e
            }
        }

        DnsCacheManager.putNegative(host)
        throw java.net.UnknownHostException("Resolution failed for $host")
    }

    private suspend fun performParallelResolution(host: String, vpnService: VpnService?): List<InetAddress> = coroutineScope {
        // Obfuscation: send fake queries for popular domains to hide the real one
        if (ProxyStats.censorshipIntensity.value > 30 && !host.contains("google") && !host.contains("facebook")) {
            launch {
                val shadows = listOf("google.com", "bing.com", "cloudflare.com", "apple.com")
                shadows.shuffled().take(1).forEach { shadow ->
                    try { DnsProtocols.queryUdpDnsShadow(shadow, "1.1.1.1", vpnService) } catch (e: Throwable) {}
                }
            }
        }
        
        val queries = listOf<suspend () -> List<InetAddress>>(
            { DnsProtocols.queryDohRacing(host, vpnService) },
            { DnsProtocols.queryDot(host, DnsOptimizer.bestDotServer, vpnService) },
            { 
                val records = try { DnsProtocols.queryUdpDnsDetailed(host, "1.1.1.1", vpnService) } catch(e: Throwable) { emptyList() }
                if (records.isNotEmpty()) DnsCacheManager.putDetailed(host, records)
                records.map { it.address }
            },
            { 
                val records = try { DnsProtocols.queryUdpDnsDetailed(host, "8.8.8.8", vpnService) } catch(e: Throwable) { emptyList() }
                if (records.isNotEmpty()) DnsCacheManager.putDetailed(host, records)
                records.map { it.address }
            },
            { DnsProtocols.queryDnsOverTcp(host, "8.8.8.8", vpnService) },
            { DnsProtocols.queryDnsOverTcp(host, "9.9.9.9", vpnService) },
            { DnsProtocols.queryUdpDnsShadow(host, "1.1.1.1", vpnService) },
            { DnsProtocols.queryUdpDnsShadow(host, "8.8.8.8", vpnService) },
            { DnsProtocols.queryUdpDnsShadow(host, "9.9.9.9", vpnService) },
            { 
                delay(600) // Slight delay for emergency fallback
                DnsCacheManager.getEmergencyFallback(host) ?: emptyList()
            }
        )
        
        val channel = kotlinx.coroutines.channels.Channel<List<InetAddress>>(queries.size)
        val activeJobs = mutableListOf<Job>()
        
        queries.forEach { query ->
            activeJobs += launch {
                val res = try { query() } catch (e: Throwable) { emptyList() }
                try { channel.send(res) } catch (e: Throwable) {}
            }
        }
        
        var result = emptyList<InetAddress>()
        val allResults = mutableListOf<List<InetAddress>>()
        var completed = 0
        while (completed < queries.size) {
            val res = try { withTimeout(5000L) { channel.receive() } } catch (e: Throwable) { emptyList() }
            if (res.isNotEmpty()) {
                allResults.add(res)
                // If we have at least 2 results, cross-verify them
                if (allResults.size >= 2) {
                    val common = allResults[0].intersect(allResults[1].toSet()).toList()
                    if (common.isNotEmpty()) {
                        result = common
                        break
                    }
                }
                // If it's a known high-trust provider (DoH), trust it immediately
                if (completed < 2) { // First 2 queries are DoH/DoT
                    result = res
                    break
                }
            }
            completed++
        }
        
        // Final fallback: use the first non-empty result if cross-verification failed
        if (result.isEmpty() && allResults.isNotEmpty()) {
            result = allResults.first()
        }
        
        activeJobs.forEach { it.cancel() }
        channel.close()
        
        if (result.isNotEmpty()) {
            val sorted = DnsCacheManager.getSortedIps(result)
            DnsCacheManager.put(host, sorted)
            return@coroutineScope sorted
        }
        
        ProxyStats.recordDnsFailure()
        if (ProxyStats.dnsFailureCount.value > 5) {
            RecoveryManager.handleEvent(RecoveryEvent.DNS_FAILURE, "Multiple sequential DNS failures")
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
