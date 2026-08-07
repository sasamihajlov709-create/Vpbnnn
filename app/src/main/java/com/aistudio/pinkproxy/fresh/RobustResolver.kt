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

    private fun getScope(): CoroutineScope = resolverScope ?: ProxyDispatcher.mainScope

    fun loadDnsSettings(context: android.content.Context) {
        BypassConfig.loadTuningSettings(context)
        DnsCacheManager.load(context)
    }

    fun saveDnsSettings(context: android.content.Context, mode: String, ip: String) {
        val dnsType = try {
            DnsType.valueOf(mode.uppercase())
        } catch (e: Exception) {
            DnsType.AUTO
        }
        BypassConfig.saveDnsSettings(context, dnsType, ip)
    }

    fun getCached(host: String, type: Int = 1): List<InetAddress>? = DnsCacheManager.getCached(host, type)
    fun getCachedDetailed(host: String, type: Int = 1): List<DnsPacketEngine.DnsRecord>? = DnsCacheManager.getCachedDetailed(host, type)

    fun clearCache() = DnsCacheManager.clearAll()
    
    suspend fun resolveDnsOverTcpOnly(host: String, vpnService: VpnService? = null, type: Int = 1): List<InetAddress> {
        val cached = DnsCacheManager.getCached(host, type)
        if (cached != null) return cached
        
        val dnsType = BypassConfig.dnsType
        val isCustom = dnsType == DnsType.CUSTOM_DOH || dnsType == DnsType.CUSTOM_TCP || dnsType == DnsType.CUSTOM_UDP
        val servers = if (isCustom) listOf(BypassConfig.customDnsUrl) else listOf("8.8.8.8", "1.1.1.1", "9.9.9.9")
        for (dns in servers) {
            try {
                val res = DnsProtocols.queryDnsOverTcp(host, dns, vpnService, type)
                if (res.isNotEmpty()) {
                    DnsCacheManager.put(host, res, type = type)
                    return res
                }
            } catch (e: java.io.IOException) {
                Log.v("RobustResolver", "DnsOverTcp failed for $host via $dns: ${e.message}")
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.v("RobustResolver", "Unexpected error in DnsOverTcp for $host: ${e.message}")
            } catch (e: Throwable) {
                Log.e("RobustResolver", "Critical DnsOverTcp error", e)
            }
        }
        return emptyList()
    }

    @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
    suspend fun resolve(host: String, vpnService: VpnService? = null, type: Int = 1): List<InetAddress> {
        if (DnsCacheManager.isIpAddress(host)) {
            return try {
                listOf(InetAddress.getByName(host))
            } catch (e: java.net.UnknownHostException) {
                Log.v("RobustResolver", "Failed to parse IP $host: ${e.message}")
                emptyList()
            } catch (e: Exception) {
                Log.v("RobustResolver", "Unexpected error parsing IP $host: ${e.message}")
                emptyList()
            }
        }
        if (DnsCacheManager.isNegative(host)) return emptyList()

        val cached = DnsCacheManager.getCached(host, type)
        if (cached != null) return cached

        val cacheKey = if (type == 1) host.lowercase() else "${host.lowercase()}:$type"
        val scope = getScope()
        val deferred = pendingResolutions.computeIfAbsent(cacheKey) {
            scope.async {
                try {
                    performResolution(host, vpnService, type)
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
            Log.v("RobustResolver", "Resolution timeout for $host")
            pendingResolutions.remove(cacheKey)
            DnsCacheManager.getCachedOrStale(host, type) ?: emptyList()
        } catch (e: CancellationException) {
            pendingResolutions.remove(cacheKey)
            throw e
        } catch (e: Exception) {
            Log.v("RobustResolver", "Resolution error for $host: ${e.message}")
            pendingResolutions.remove(cacheKey)
            DnsCacheManager.getCachedOrStale(host, type) ?: emptyList()
        } catch (e: Throwable) {
            Log.e("RobustResolver", "Critical resolution error for $host", e)
            pendingResolutions.remove(cacheKey)
            emptyList()
        }
    }

    suspend fun resolveDual(host: String, vpnService: VpnService? = null): List<InetAddress> = coroutineScope {
        if (!BypassConfig.includeIpv6) return@coroutineScope resolve(host, vpnService, 1)

        val deferredA = async { try { resolve(host, vpnService, 1) } catch (e: Exception) { emptyList() } }
        val deferredAaaa = async { try { resolve(host, vpnService, 28) } catch (e: Exception) { emptyList() } }

        val a = deferredA.await()
        val aaaa = deferredAaaa.await()
        
        // Prefer AAAA if available, but return all for selection
        (aaaa + a).distinct()
    }

    private suspend fun performResolution(host: String, vpnService: VpnService?, type: Int = 1): List<InetAddress> {
        val censorship = BypassConfig.censorshipLevel
        if (censorship > 50) {
            return performParallelResolution(host, vpnService, type)
        }
        
        val isCensored = BypassConfig.isHostCensored(host)
        val isDirect = BypassConfig.isHostDirect(host)

        // 1. Try Direct if not censored
        if (isDirect && !isCensored) {
            try {
                val res = DnsProtocols.queryUdpDnsShadow(host, "8.8.8.8", vpnService, type)
                if (res.isNotEmpty() && !DnsCacheManager.isPoisoned(res.first(), host)) {
                    DnsCacheManager.put(host, res, type = type)
                    return res
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.v("RobustResolver", "Shadow UDP DNS failed for $host: ${e.message}")
            }
        }

        // 2. Try Smart Parallel Resolution (DoH, DoT, Shadow UDP)
        try {
            if (ProxyStats.censorshipIntensity.value > 95) {
                val cached = DnsCacheManager.getCached(host, type) ?: DnsCacheManager.getCachedOrStale(host, type)
                if (cached != null) return cached
            }
            
            val par = performParallelResolution(host, vpnService, type)
            if (par.isNotEmpty()) {
                if (DnsCacheManager.isSuspicious(host, par)) {
                    ProxyStats.recordDpiEvent(DpiType.DNS_POISONING)
                } else {
                    val sorted = DnsCacheManager.getSortedIps(par)
                    DnsCacheManager.put(host, sorted, type = type)
                    
                    // Smart Prefetch common subdomains with throttling
                    if (type == 1 && !host.startsWith("www.") && host.split(".").size == 2 && !BypassConfig.isPowerSaveMode) {
                        getScope().launch {
                            listOf("www.", "api.", "assets.", "static.", "m.").forEach { prefix ->
                                try { 
                                    delay(if (BypassConfig.batteryLevel < 30) 1500L else 500L) // Longer delay on low battery
                                    val preHost = prefix + host
                                    if (DnsCacheManager.getCached(preHost) == null) {
                                        performParallelResolution(preHost, vpnService, 1) 
                                    }
                                } catch (e: CancellationException) {
                                    throw e
                                } catch (e: Exception) { 
                                    Log.v("RobustResolver", "Prefetch failed for $prefix$host: ${e.message}")
                                }
                            }
                        }
                    }
                    return sorted
                }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.v("RobustResolver", "Parallel resolution failed for $host: ${e.message}")
        }

        // 3. Emergency Fallback & Stale Cache
        DnsCacheManager.getCachedOrStale(host, type)?.let {
            DnsCacheManager.put(host, it, type = type)
            return it
        }

        // 4. UDP/TCP Fallbacks
        val dnsType = BypassConfig.dnsType
        val isCustom = dnsType == DnsType.CUSTOM_DOH || dnsType == DnsType.CUSTOM_TCP || dnsType == DnsType.CUSTOM_UDP
        val servers = if (isCustom) listOf(BypassConfig.customDnsUrl) else listOf("8.8.8.8", "1.1.1.1", "9.9.9.9")
        for (dns in servers) {
            try {
                val res = DnsProtocols.queryUdpDnsShadow(host, dns, vpnService, type)
                if (res.isNotEmpty()) {
                    DnsCacheManager.put(host, res, type = type)
                    return res
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.v("RobustResolver", "Fallback UDP DNS failed for $host via $dns: ${e.message}")
            }
        }

        DnsCacheManager.putNegative(host)
        throw java.net.UnknownHostException("Resolution failed for $host")
    }

    private suspend fun performParallelResolution(host: String, vpnService: VpnService?, type: Int = 1): List<InetAddress> = coroutineScope {
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
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.v("RobustResolver", "Fake query error: ${e.message}")
                } catch (e: Throwable) {
                    Log.v("RobustResolver", "Critical fake query error: ${e.message}")
                }
                }
            }
        }
        
        val primaryDoH: suspend () -> List<InetAddress> = { DnsProtocols.queryDohRacing(host, vpnService, type) }
        val primaryDoT: suspend () -> List<InetAddress> = { DnsProtocols.queryDot(host, DnsOptimizer.bestDotServer, vpnService, type) }
        val shadowUdp: suspend () -> List<InetAddress> = { DnsProtocols.queryUdpDnsShadow(host, "1.1.1.1", vpnService, type) }
        val shadowTcp: suspend () -> List<InetAddress> = { DnsProtocols.queryTcpDnsShadow(host, "8.8.8.8", vpnService, type) }
        val dnsQuic: suspend () -> List<InetAddress> = { DnsProtocols.queryDnsOverQuic(host, DnsOptimizer.bestDoqServer, vpnService, type) }
        val echCheck: suspend () -> List<InetAddress> = {
            try {
                val httpsRecords = DnsProtocols.queryHttpsRecord(host, vpnService)
                if (httpsRecords.isNotEmpty()) {
                    DnsCacheManager.putEchSupport(host, true)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.v("RobustResolver", "ECH check error: ${e.message}")
            } catch (e: Throwable) {
                Log.v("RobustResolver", "Critical ECH check error: ${e.message}")
            }
            emptyList()
        }
        val fallbackDns: suspend () -> List<InetAddress> = {
            delay(1000)
            DnsCacheManager.getEmergencyFallback(host) ?: emptyList()
        }

        val queries = mutableListOf<suspend () -> List<InetAddress>>()
        queries.add(primaryDoH)
        queries.add(primaryDoT)
        queries.add(shadowUdp)
        queries.add(shadowTcp)
        queries.add(dnsQuic)
        queries.add(echCheck)

        if (intensity > 60) {
            queries.add { DnsProtocols.queryDnsExtremeRacing(host, vpnService, type) }
            queries.add { DnsProtocols.queryDohSmuggling(host, vpnService, type) }
        }
        if (intensity > 70) {
            queries.add { DnsProtocols.queryUdpDnsNuclear(host, "8.8.8.8", vpnService, type) }
        }
        if (intensity > 85) {
            queries.add { DnsProtocols.queryTcpDnsNuclear(host, "8.8.8.8", vpnService, type) }
        }

        val channel = kotlinx.coroutines.channels.Channel<List<InetAddress>>(queries.size + 1)

        // Grouped Happy Eyeballs-like staggered start
        val queryGroups = listOf(
            listOf(primaryDoH, shadowUdp),
            listOf(primaryDoT, dnsQuic),
            listOf(shadowTcp, echCheck),
            queries.filter { it !in listOf(primaryDoH, primaryDoT, shadowUdp, shadowTcp, dnsQuic, echCheck) }
        )

        val staggerDelay = if (BypassConfig.isPowerSaveMode || BypassConfig.batteryLevel < 15) 600L else 250L // 250ms delay between groups if no result yet

        launch {
            for (group in queryGroups) {
                if (group.isEmpty()) continue
                group.forEach { query ->
                    launch {
                        val res = try { query() } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            emptyList()
                        } catch (e: Throwable) {
                            Log.e("RobustResolver", "Critical query failure", e)
                            emptyList()
                        }
                        try { channel.send(res) } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            Log.v("RobustResolver", "Failed to send result to channel: ${e.message}")
                        } catch (e: Throwable) {
                            Log.v("RobustResolver", "Critical error sending result to channel: ${e.message}")
                        }
                    }
                }

                delay(staggerDelay)
            }

            // Finally launch emergency fallback if nothing worked after staggered starts
            launch {
                val res = try { fallbackDns() } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    emptyList()
                } catch (e: Throwable) {
                    emptyList()
                }
                try { channel.send(res) } catch (e: Exception) {
                    Log.v("RobustResolver", "Failed to send fallback result to channel: ${e.message}")
                } catch (e: Throwable) {
                    Log.v("RobustResolver", "Critical error sending fallback result to channel: ${e.message}")
                }
            }
        }
        
        var result = emptyList<InetAddress>()
        val receivedResults = mutableListOf<List<InetAddress>>()
        var completed = 0
        
        try {
            while (completed < queries.size) {
                val res = try { withTimeout(5000L) { channel.receive() } } catch (e: CancellationException) {
                    if (e !is TimeoutCancellationException) throw e
                    emptyList()
                } catch (e: Exception) {
                    emptyList()
                } catch (e: Throwable) {
                    emptyList()
                }
                if (res.isNotEmpty()) {
                    // Check if any of these were detailed records with TTL
                    val detailed = DnsCacheManager.getCachedDetailed(host, type)
                    val cleanRes = res.filter { ip ->
                        val recordTtl = detailed?.find { it.address == ip }?.ttlSeconds ?: -1L
                        !DnsPacketEngine.isSuspicious(ip, host, recordTtl)
                    }
                    
                    if (cleanRes.isEmpty()) {
                        ProxyStats.recordDpiEvent(DpiType.DNS_POISONING)
                        ProxyStats.recordCensorshipEvent(true) // Повышаем интенсивность при отравлении
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
        } finally {
            // Cancel all other ongoing resolution attempts
            this.coroutineContext.cancelChildren()
            channel.close()
        }
        
        // Final fallback: use the first received result if loop ended
        if (result.isEmpty() && receivedResults.isNotEmpty()) {
            result = receivedResults.first()
        }
        
        if (result.isNotEmpty()) {
            val sorted = DnsCacheManager.getSortedIps(result)
            DnsCacheManager.put(host, sorted, type = type)
            ProxyStats.recordDnsResult(true)
            return@coroutineScope sorted
        }
        
        DnsCacheManager.putNegative(host)
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
        DnsOptimizer.stop()
    }
}
