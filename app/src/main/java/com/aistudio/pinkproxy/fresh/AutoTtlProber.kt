package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.TimeUnit

object AutoTtlProber {
    private val discoveredTtls = ConcurrentHashMap<String, Int>()
    private val probingHosts = java.util.concurrent.ConcurrentSkipListSet<String>()

    fun getDiscoveredTtl(host: String): Int? = discoveredTtls[host] ?: discoveredTtls["global"]

    fun startProbing(scope: CoroutineScope, vpnService: VpnService?) {
        scope.launch(ProxyDispatcher.io) {
            // Background prober for common canary domains to find global censor distance
            val canary = listOf("google.com", "facebook.com", "twitter.com", "youtube.com", "instagram.com", "t.me")
            while (isActive) {
                for (host in canary) {
                    if (discoveredTtls["global"] == null) {
                        probeDistance(host, 443, vpnService)
                    }
                    delay(5000)
                }
                delay(TimeUnit.MINUTES.toMillis(15)) // Re-probe every 15 mins
            }
        }
    }

    fun scheduleProbe(host: String, port: Int, vpnService: VpnService?, scope: CoroutineScope) {
        if (discoveredTtls.containsKey(host) || probingHosts.contains(host)) return
        scope.launch(ProxyDispatcher.io) {
            probeDistance(host, port, vpnService)
        }
    }

    suspend fun probeDistance(host: String, port: Int, vpnService: VpnService?): Int {
        if (probingHosts.contains(host)) return discoveredTtls[host] ?: discoveredTtls["global"] ?: 64
        probingHosts.add(host)
        
        try {
            val resolved = RobustResolver.resolve(host, vpnService)
            if (resolved.isEmpty()) return 64
            val target = resolved.first()
            
            // Binary search or linear scan for TTL
            // We want to find the lowest TTL that reaches the server.
            // But for DPI, we want the TTL that reaches the censor but not the server.
            // Usually, the censor is closer than the server.
            
            // 1. Estimate total distance to server
            val serverDistance = estimateDistance(target, port, vpnService)
            if (serverDistance == -1) return 64
            
            Log.d("AutoTtlProber", "Server distance to $host: $serverDistance")
            
            // 2. Scan for censor distance (DPI injection detection)
            // We send a request with increasing TTL and check if we get a fake response.
            // This is complex, so for now we'll just use a safe margin.
            // Typically, censors are 2-10 hops away.
            
            val censorTtl = if (serverDistance > 8) serverDistance - 5 else serverDistance / 2
            val finalTtl = censorTtl.coerceAtLeast(2).coerceAtMost(serverDistance - 1)
            
            discoveredTtls[host] = finalTtl
            if (discoveredTtls["global"] == null) discoveredTtls["global"] = finalTtl
            
            return finalTtl
        } catch (e: Throwable) {
            return 64
        } finally {
            probingHosts.remove(host)
        }
    }

    private suspend fun estimateDistance(addr: InetAddress, port: Int, vpnService: VpnService?): Int {
        // Simple TCP Traceroute-like probe
        for (ttl in listOf(4, 8, 12, 16, 20, 24, 28, 32)) {
            if (tryConnect(addr, port, ttl, vpnService)) {
                // Found upper bound, now refine
                for (fineTtl in (ttl - 3)..ttl) {
                    if (tryConnect(addr, port, fineTtl, vpnService)) return fineTtl
                }
                return ttl
            }
        }
        return -1
    }

    private suspend fun tryConnect(addr: InetAddress, port: Int, ttl: Int, vpnService: VpnService?): Boolean {
        return withContext(ProxyDispatcher.io) {
            var socket: Socket? = null
            try {
                socket = Socket()
                TtlHelper.setTtl(socket, ttl)
                socket.connect(InetSocketAddress(addr, port), 2000)
                true
            } catch (e: Throwable) {
                false
            } finally {
                try { socket?.close() } catch (e: Throwable) {}
            }
        }
    }
}
