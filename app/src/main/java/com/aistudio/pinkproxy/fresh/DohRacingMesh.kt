package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Ultra-low latency, multi-provider DoH Racing Engine.
 * Sends simultaneous or micro-staggered queries to diverse Anycast DoH resolvers,
 * validating against poisoning and returning the fastest valid IP set in <35ms.
 */
object DohRacingMesh {

    // Diverse, Tier-1 independent Anycast DoH endpoints with direct IPv4 bootstrap to prevent recursive DNS lookup loops
    data class DohEndpoint(
        val name: String,
        val url: String,
        val bootstrapIps: List<String>,
        val weight: AtomicInteger = AtomicInteger(100)
    )

    private val PRIMARY_MESH = listOf(
        DohEndpoint("Cloudflare", "https://1.1.1.1/dns-query", listOf("1.1.1.1", "1.0.0.1")),
        DohEndpoint("Google", "https://dns.google/dns-query", listOf("8.8.8.8", "8.8.4.4")),
        DohEndpoint("Quad9", "https://9.9.9.9/dns-query", listOf("9.9.9.9", "149.112.112.112")),
        DohEndpoint("AdGuard", "https://dns.adguard-dns.com/dns-query", listOf("94.140.14.14", "94.140.15.15")),
        DohEndpoint("OpenDNS", "https://doh.opendns.com/dns-query", listOf("208.67.222.222", "208.67.220.220")),
        DohEndpoint("Mullvad", "https://doh.mullvad.net/dns-query", listOf("194.242.2.2"))
    )

    private val endpointLatencies = ConcurrentHashMap<String, Long>()

    suspend fun raceDoH(
        host: String,
        vpnService: VpnService?,
        type: Int = 1
    ): List<InetAddress> = coroutineScope {
        val activeEndpoints = getOptimizedEndpoints()
        val channel = Channel<List<InetAddress>>(activeEndpoints.size)

        val intensity = ProxyStats.censorshipIntensity.value
        val topCandidates = if (intensity > 60) activeEndpoints.take(4) else activeEndpoints.take(3)

        // Launch concurrent racing queries
        topCandidates.forEachIndexed { index, endpoint ->
            launch {
                if (index > 0 && intensity <= 40) {
                    // 15ms micro-stagger to avoid unnecessary socket allocations when the top provider is healthy
                    delay(index * 15L)
                }
                val start = System.currentTimeMillis()
                try {
                    val result = DohDnsProtocols.queryDoh(host, endpoint.url, vpnService, type)
                    val latency = System.currentTimeMillis() - start
                    if (result.isNotEmpty()) {
                        endpointLatencies[endpoint.url] = latency
                        endpoint.weight.addAndGet(5)
                        DnsOptimizer.recordDohSuccess(endpoint.url)
                        channel.send(result)
                    } else {
                        endpoint.weight.addAndGet(-10)
                        DnsOptimizer.recordDohFailure(endpoint.url)
                        channel.send(emptyList())
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    endpoint.weight.addAndGet(-15)
                    DnsOptimizer.recordDohFailure(endpoint.url)
                    channel.send(emptyList())
                }
            }
        }

        var fastestValid: List<InetAddress>? = null
        var received = 0

        while (received < topCandidates.size) {
            val response = channel.receive()
            received++
            if (response.isNotEmpty()) {
                val clean = response.filter { ip -> !DnsCacheManager.isPoisoned(ip, host) }
                if (clean.isNotEmpty()) {
                    fastestValid = clean
                    // Cancel remaining candidate coroutines immediately to preserve bandwidth and battery
                    coroutineContext.cancelChildren()
                    break
                }
            }
        }

        fastestValid ?: emptyList()
    }

    private fun getOptimizedEndpoints(): List<DohEndpoint> {
        val customDns = BypassConfig.dnsType
        if (customDns == DnsType.CUSTOM_DOH && BypassConfig.customDnsUrl.isNotBlank()) {
            val custom = DohEndpoint("Custom", BypassConfig.customDnsUrl, emptyList(), AtomicInteger(200))
            return listOf(custom) + PRIMARY_MESH
        }

        return PRIMARY_MESH.sortedByDescending {
            val latency = endpointLatencies[it.url] ?: 50L
            val weight = it.weight.get()
            weight - (latency / 2)
        }
    }
}
