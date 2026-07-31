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

    private val discoveredMtus = ConcurrentHashMap<String, Int>()

    fun getDiscoveredMtu(host: String): Int = discoveredMtus[host] ?: discoveredMtus["global"] ?: 1400

    fun startProbing(scope: CoroutineScope, vpnService: VpnService?) {
        scope.launch(ProxyDispatcher.io) {
            // Background prober for common canary domains to find global censor distance
            val canary = listOf("google.com", "facebook.com", "twitter.com", "youtube.com", "instagram.com", "t.me")
            while (isActive) {
                for (host in canary) {
                    if (discoveredTtls["global"] == null) {
                        probeDistance(host, 443, vpnService)
                    }
                    if (discoveredMtus["global"] == null) {
                        probeBestMtu(host, 443, vpnService)
                    }
                    delay(5000)
                }
                delay(TimeUnit.MINUTES.toMillis(15)) // Re-probe every 15 mins
            }
        }
    }

    fun scheduleProbe(host: String, port: Int, vpnService: VpnService?, scope: CoroutineScope) {
        if ((discoveredTtls.containsKey(host) && discoveredMtus.containsKey(host)) || probingHosts.contains(host)) return
        scope.launch(ProxyDispatcher.io) {
            if (!discoveredTtls.containsKey(host)) probeDistance(host, port, vpnService)
            if (!discoveredMtus.containsKey(host)) probeBestMtu(host, port, vpnService)
        }
    }

    suspend fun probeBestMtu(host: String, port: Int, vpnService: VpnService?): Int {
        if (probingHosts.contains(host + "_mtu")) return discoveredMtus[host] ?: discoveredMtus["global"] ?: 1400
        probingHosts.add(host + "_mtu")
        try {
            val resolved = RobustResolver.resolve(host, vpnService)
            if (resolved.isEmpty()) return 1400
            val target = resolved.first()
            
            // Binary search for MTU
            var low = 576
            var high = 1500
            var best = 1400
            
            while (low <= high) {
                val mid = (low + high) / 2
                if (tryMtu(target, port, mid, vpnService)) {
                    best = mid
                    low = mid + 1
                } else {
                    high = mid - 1
                }
                delay(100)
            }
            
            discoveredMtus[host] = best
            val currentGlobal = discoveredMtus["global"] ?: 1400
            discoveredMtus["global"] = (currentGlobal * 0.8 + best * 0.2).toInt().coerceIn(576, 1500)
            
            if (best < 1300) {
                ProxyStats.logRecovery("MTU Probe Result for $host: $best (Fragmented path detected)")
            }
            return best
        } catch (e: Throwable) {
            return 1400
        } finally {
            probingHosts.remove(host + "_mtu")
        }
    }

    private suspend fun tryMtu(addr: InetAddress, port: Int, mtu: Int, vpnService: VpnService?): Boolean {
        return withContext(ProxyDispatcher.io) {
            var socket: Socket? = null
            try {
                socket = Socket()
                vpnService?.protect(socket)
                socket.tcpNoDelay = true
                // We simulate MTU by setting MSS which is MTU - 40 (TCP+IP headers)
                TtlHelper.setMss(socket, (mtu - 40).coerceAtLeast(512))
                socket.connect(InetSocketAddress(addr, port), 2000)
                
                val output = socket.getOutputStream()
                val payload = ByteArray(mtu - 40) { 0 } // Full size segment
                output.write(payload)
                output.flush()
                
                // If it doesn't time out, the MTU is likely okay
                socket.soTimeout = 1500
                socket.getInputStream().read()
                true
            } catch (e: Throwable) {
                false
            } finally {
                try { socket?.close() } catch (e: Throwable) {}
            }
        }
    }

    suspend fun probeDistance(host: String, port: Int, vpnService: VpnService?): Int {
        if (probingHosts.contains(host)) return discoveredTtls[host] ?: discoveredTtls["global"] ?: 64
        probingHosts.add(host)
        
        try {
            val resolved = RobustResolver.resolve(host, vpnService)
            if (resolved.isEmpty()) return 64
            val target = resolved.first()
            
            // 1. Estimate distance to server using ICMP or TCP SYN
            val serverDistance = estimateDistance(target, port, vpnService)
            if (serverDistance == -1) return 64
            
            Log.d("AutoTtlProber", "Server distance to $host: $serverDistance")
            
            // 2. Identify censor distance
            // We look for the first hop that returns a response when we send something "forbidden"
            // but doesn't reach the server.
            val censorDistance = identifyCensorHop(target, port, serverDistance, vpnService)
            
            val finalTtl = if (censorDistance != -1) {
                censorDistance // Target the censor exactly
            } else {
                // Fallback: stay safe, usually censors are close (2-10 hops)
                (serverDistance - 4).coerceAtLeast(3).coerceAtMost(serverDistance - 1)
            }
            
            discoveredTtls[host] = finalTtl
            updateGlobalConsensus(finalTtl)
            
            return finalTtl
        } catch (e: Throwable) {
            return 64
        } finally {
            probingHosts.remove(host)
        }
    }

    private fun updateGlobalConsensus(newTtl: Int) {
        val currentGlobal = discoveredTtls["global"] ?: 0
        if (currentGlobal == 0) {
            discoveredTtls["global"] = newTtl
        } else {
            // Weighted moving average for global TTL
            discoveredTtls["global"] = (currentGlobal * 0.7 + newTtl * 0.3).toInt().coerceIn(2, 20)
        }
    }

    private suspend fun identifyCensorHop(addr: InetAddress, port: Int, serverDist: Int, vpnService: VpnService?): Int {
        // We try to trigger a RST or fake response from censor with increasing TTL
        // starting from a very low value.
        for (ttl in 2 until serverDist) {
            if (isCensorTriggered(addr, port, ttl, vpnService)) {
                return ttl
            }
        }
        return -1
    }

    private suspend fun isCensorTriggered(addr: InetAddress, port: Int, ttl: Int, vpnService: VpnService?): Boolean {
        return withContext(ProxyDispatcher.io) {
            var socket: Socket? = null
            try {
                socket = Socket()
                TtlHelper.setTtl(socket, ttl)
                socket.connect(InetSocketAddress(addr, port), 1500)
                
                val output = socket.getOutputStream()
                val input = socket.getInputStream()
                
                // Send a fake SNI that might be blocked
                val fakeHello = FakePacketHelper.buildRealisticTlsHello("blocked.com")
                output.write(fakeHello); output.flush()
                
                // If we get an immediate RST or some data back despite low TTL, it's the censor
                val buffer = ByteArray(1024)
                socket.soTimeout = 1000
                val read = input.read(buffer)
                
                read > 0 // If we got data back, it reached the censor (or server, but TTL is low)
            } catch (e: java.net.SocketTimeoutException) {
                false
            } catch (e: Throwable) {
                // Likely a RST from censor
                e.message?.contains("reset", true) == true
            } finally {
                try { socket?.close() } catch (e: Throwable) {}
            }
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
