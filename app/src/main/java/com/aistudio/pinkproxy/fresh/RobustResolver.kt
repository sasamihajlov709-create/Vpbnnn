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
    fun getCachedDetailed(host: String): List<DnsPacketEngine.DnsRecord>? = DnsCacheManager.getCachedDetailed(host)

    fun clearCache() = DnsCacheManager.clear()
    
    suspend fun resolveDnsOverTcpOnly(host: String, vpnService: VpnService? = null): List<InetAddress> {
        val cached = DnsCacheManager.getCached(host)
        if (cached != null) return cached
        
        val servers = if (dnsMode == "Custom") listOf(customDnsIp) else listOf("8.8.8.8", "1.1.1.1", "9.9.9.9")
        for (dns in servers) {
            try {
                val res = DnsProtocols.queryDnsOverTcp(host, dns, vpnService)
                if (res.isNotEmpty()) {
                    DnsCacheManager.put(host, res)
                    return res
                }
            } catch (e: Throwable) {}
        }
        return emptyList()
    }

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
        } catch (e: TimeoutCancellationException) {
            pendingResolutions.remove(cacheKey)
            DnsCacheManager.getEmergencyFallback(host) ?: emptyList()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            pendingResolutions.remove(cacheKey)
            DnsCacheManager.getEmergencyFallback(host) ?: emptyList()
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
        val intensity = ProxyStats.censorshipIntensity.value
        // Obfuscation: send fake queries for popular domains to hide the real one
        if (ProxyStats.censorshipIntensity.value > 40 && !host.contains("google") && !host.contains("facebook")) {
            launch {
                val shadows = listOf("google.com", "bing.com", "cloudflare.com", "apple.com", "microsoft.com", "amazon.com", "wikipedia.org", "netflix.com")
                val rnd = java.util.concurrent.ThreadLocalRandom.current()
                shadows.shuffled().take(rnd.nextInt(2, 5)).forEach { shadow ->
                    try { 
                        delay(rnd.nextLong(10, 100))
                        DnsProtocols.queryUdpDnsShadow(shadow, "8.8.8.8", vpnService) 
                    } catch (e: Throwable) {}
                }
            }
        }
        
        val queries = mutableListOf<suspend () -> List<InetAddress>>()
        
        // 1. Primary DoH (Very Reliable)
        queries.add { DnsProtocols.queryDohRacing(host, vpnService) }
        
        // 2. DoT or fallback DoH
        queries.add { DnsProtocols.queryDot(host, DnsOptimizer.bestDotServer, vpnService) }
        
        // 3. UDP with Shadow (Fast, evasion enabled)
        queries.add { DnsProtocols.queryUdpDnsShadow(host, "1.1.1.1", vpnService) }
        
        // 4. TCP with Shadow (For extreme evasion)
        queries.add { DnsProtocols.queryTcpDnsShadow(host, "8.8.8.8", vpnService) }
        
        // 4.1 TCP Nuclear (For maximum resilience)
        if (intensity > 85) {
            queries.add { DnsProtocols.queryTcpDnsNuclear(host, "8.8.8.8", vpnService) }
        }
        
        // 4.3 DNS over QUIC (Shadow/Pseudo-QUIC for UDP:443 evasion)
        queries.add { DnsProtocols.queryDnsOverQuic(host, "8.8.8.8", vpnService) }
        
        // 4.5 DoH Smuggling (Experimental resilience)
        if (intensity > 60) {
            queries.add { DnsProtocols.queryDohSmuggling(host, vpnService) }
        }
        
        // 5. Background ECH check (does not block main resolution)
        queries.add { 
            try {
                val httpsRecords = DnsProtocols.queryHttpsRecord(host, vpnService)
                if (httpsRecords.isNotEmpty()) {
                    DnsCacheManager.putEchSupport(host, true)
                }
            } catch (e: Throwable) {}
            emptyList()
        }
        
        // 6. Emergency Fallback
        queries.add { 
            delay(1000) 
            DnsCacheManager.getEmergencyFallback(host) ?: emptyList()
        }
        
        val channel = kotlinx.coroutines.channels.Channel<List<InetAddress>>(queries.size)
        val activeJobs = mutableListOf<Job>()
        
        queries.forEach { query ->
            activeJobs += launch {
                val res = try { query() } catch (e: Throwable) { 
                    if (e is CancellationException) throw e
                    emptyList() 
                }
                try { channel.send(res) } catch (e: Throwable) {}
            }
        }
        
        var result = emptyList<InetAddress>()
        val receivedResults = mutableListOf<List<InetAddress>>()
        var completed = 0
        
        while (completed < queries.size) {
            val res = try { withTimeout(5000L) { channel.receive() } } catch (e: Throwable) { 
                if (e !is TimeoutCancellationException && e is CancellationException) throw e
                emptyList() 
            }
            if (res.isNotEmpty()) {
                // Check if any of these were detailed records with TTL
                val detailed = DnsCacheManager.getCachedDetailed(host)
                val cleanRes = res.filter { ip ->
                    val recordTtl = detailed?.find { it.address == ip }?.ttlSeconds ?: -1L
                    !DnsPacketEngine.isSuspicious(ip, host, recordTtl)
                }
                
                if (cleanRes.isEmpty()) {
                    ProxyStats.recordDpiEvent(DpiType.DNS_POISONING)
                    completed++
                    continue
                }
                
                // IP Verification Step: If high censorship, verify at least one IP from the result
                if (intensity > 85 && (completed % 2 == 0 || receivedResults.isEmpty())) {
                    val verified = DnsOptimizer.verifyIp(host, cleanRes.first(), vpnService)
                    if (!verified) {
                        Log.w("RobustResolver", "Verification failed for ${cleanRes.first()} on $host (Poisoned IP?)")
                        ProxyStats.recordDpiEvent(DpiType.DNS_POISONING)
                        completed++
                        continue
                    }
                }
                
                receivedResults.add(cleanRes)
                
                // Fast path: As soon as we receive a clean resolution from any secure resolver, return immediately
                if (cleanRes.isNotEmpty()) {
                    result = cleanRes
                    break
                }
            }
            completed++
        }
        
        // Final fallback: use the first received result if loop ended
        if (result.isEmpty() && receivedResults.isNotEmpty()) {
            result = receivedResults.first()
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
