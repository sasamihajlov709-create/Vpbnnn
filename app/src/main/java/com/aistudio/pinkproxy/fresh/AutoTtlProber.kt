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
    private val networkTtls = ConcurrentHashMap<String, ConcurrentHashMap<String, Int>>()
    private val networkMtus = ConcurrentHashMap<String, ConcurrentHashMap<String, Int>>()
    private val probingHosts = java.util.concurrent.ConcurrentSkipListSet<String>()

    fun getDiscoveredTtl(host: String): Int? {
        val netType = BypassConfig.getNetworkType().toString()
        return networkTtls[netType]?.get(host) ?: networkTtls[netType]?.get("global") ?: discoveredTtls[host] ?: discoveredTtls["global"]
    }

    private val discoveredMtus = ConcurrentHashMap<String, Int>()

    fun getDiscoveredMtu(host: String): Int {
        val netType = BypassConfig.getNetworkType().toString()
        return networkMtus[netType]?.get(host) ?: networkMtus[netType]?.get("global") ?: discoveredMtus[host] ?: discoveredMtus["global"] ?: 1400
    }

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
                
                // Cleanup overgrown caches to prevent memory leak
                if (discoveredTtls.size > 1000) {
                    val globalTtl = discoveredTtls["global"]
                    discoveredTtls.clear()
                    if (globalTtl != null) discoveredTtls["global"] = globalTtl
                }
                if (discoveredMtus.size > 1000) {
                    val globalMtu = discoveredMtus["global"]
                    discoveredMtus.clear()
                    if (globalMtu != null) discoveredMtus["global"] = globalMtu
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
                TtlHelper.setMss(socket, (mtu - 40).coerceAtLeast(512))
                socket.connect(InetSocketAddress(addr, port), 1500)
                
                val output = socket.getOutputStream()
                val payload = ByteArray(mtu - 40) { 0 }
                output.write(payload)
                output.flush()
                
                socket.soTimeout = 1000
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
        val netType = BypassConfig.getNetworkType().toString()
        val netMap = networkTtls.getOrPut(netType) { ConcurrentHashMap() }
        val currentGlobal = netMap["global"] ?: 0
        if (currentGlobal == 0) {
            netMap["global"] = newTtl
        } else {
            netMap["global"] = (currentGlobal * 0.6 + newTtl * 0.4).toInt().coerceIn(2, 30)
        }
        discoveredTtls["global"] = netMap["global"]!!
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
                socket.connect(InetSocketAddress(addr, port), 1000)
                
                val output = socket.getOutputStream()
                val input = socket.getInputStream()
                
                // Use a multi-stage trigger: TLS SNI + HTTP Host header
                val rnd = ThreadLocalRandom.current()
                val trigger = when(rnd.nextInt(3)) {
                    0 -> FakePacketHelper.buildRealisticTlsHello("blocked.com")
                    1 -> "GET / HTTP/1.1\r\nHost: blocked.com\r\n\r\n".toByteArray()
                    else -> FakePacketHelper.buildHttpChaosPacket()
                }
                output.write(trigger); output.flush()
                
                // If we get data back despite low TTL, it's either the censor or we reached the server
                // We check the first few bytes to see if it's a typical block page or TLS alert
                val buffer = ByteArray(1024)
                socket.soTimeout = 800
                val read = try { input.read(buffer) } catch(e: Throwable) { -2 }
                
                if (read > 0) {
                    val content = String(buffer, 0, read.coerceAtMost(128), Charsets.US_ASCII).lowercase()
                    // If it's a block page or TLS Alert, it's definitely the censor
                    content.contains("forbidden") || content.contains("block") || buffer[0] == 0x15.toByte() || read > 0
                } else {
                    false
                }
            } catch (e: java.net.SocketTimeoutException) {
                false
            } catch (e: Throwable) {
                // RST/FIN from middlebox is a clear indicator
                val msg = e.message?.lowercase() ?: ""
                msg.contains("reset") || msg.contains("closed") || msg.contains("pipe")
            } finally {
                try { socket?.close() } catch (e: Throwable) {}
            }
        }
    }

    private suspend fun estimateDistance(addr: InetAddress, port: Int, vpnService: VpnService?): Int {
        return kotlinx.coroutines.withContext(ProxyDispatcher.io) {
            kotlinx.coroutines.coroutineScope {
                val ttls = listOf(4, 8, 12, 16, 20, 24, 28, 32)
                val deferreds = ttls.associateWith { ttl -> 
                    async { tryConnect(addr, port, ttl, vpnService) }
                }
            
            var upperBound = -1
            for (ttl in ttls) {
                if (deferreds[ttl]?.await() == true) {
                    upperBound = ttl
                    break
                }
            }
            
            if (upperBound != -1) {
                val fineTtls = ((upperBound - 3) until upperBound).toList()
                val fineDeferreds = fineTtls.associateWith { ttl -> 
                    async { tryConnect(addr, port, ttl, vpnService) }
                }
                for (ttl in fineTtls) {
                    if (fineDeferreds[ttl]?.await() == true) return@coroutineScope ttl
                }
                return@coroutineScope upperBound
            }
            return@coroutineScope -1
            }
        }
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
