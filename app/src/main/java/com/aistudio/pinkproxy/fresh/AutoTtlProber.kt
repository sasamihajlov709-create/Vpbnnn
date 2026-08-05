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
            val canary = listOf("google.com", "facebook.com", "twitter.com", "youtube.com", "instagram.com", "t.me")
            while (isActive) {
                for (host in canary) {
                    val r = ThreadLocalRandom.current().nextInt(100)
                    if (discoveredTtls["global"] == null || r < 20) {
                        probeDistance(host, 443, vpnService)
                    }
                    if (discoveredMtus["global"] == null || r < 10) {
                        probeBestMtu(host, 443, vpnService)
                    }
                    delay(5000)
                }
                
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

                delay(TimeUnit.MINUTES.toMillis(15)) 
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
        val key = host + "_mtu"
        if (probingHosts.contains(key)) return discoveredMtus[host] ?: discoveredMtus["global"] ?: 1400
        probingHosts.add(key)
        try {
            val resolved = RobustResolver.resolve(host, vpnService)
            if (resolved.isEmpty()) return 1400
            val target = resolved.first()
            
            var low = 576
            var high = 1500
            var best = 1400
            
            while (low <= high) {
                val mid = (low + high) / 2
                if (tryMtu(target, port, mid, vpnService, host)) {
                    best = mid
                    low = mid + 1
                } else {
                    high = mid - 1
                }
                delay(50)
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
            probingHosts.remove(key)
        }
    }

    private suspend fun tryMtu(addr: InetAddress, port: Int, mtu: Int, vpnService: VpnService?, host: String = ""): Boolean {
        return withContext(ProxyDispatcher.io) {
            var socket: Socket? = null
            try {
                socket = Socket()
                vpnService?.protect(socket)
                TtlHelper.tuneSocket(socket)
                TtlHelper.setMss(socket, (mtu - 40).coerceAtLeast(512))
                socket.connect(InetSocketAddress(addr, port), 1000)
                
                val output = socket.getOutputStream()
                val payloadSize = (mtu - 40).coerceAtLeast(0)
                if (payloadSize > 0) {
                   val payload = if (port == 443) {
                       val hello = FakePacketHelper.buildRealisticTlsHello(if (host.isNotEmpty()) host else addr.hostAddress)
                       val padded = ByteArray(payloadSize)
                       System.arraycopy(hello, 0, padded, 0, minOf(hello.size, payloadSize))
                       padded
                   } else {
                       ByteArray(payloadSize)
                   }
                   output.write(payload)
                   output.flush()
                }
                
                socket.soTimeout = 800
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
            
            val serverDistance = estimateDistance(target, port, vpnService)
            if (serverDistance == -1) return 64
            
            Log.d("AutoTtlProber", "Server distance to $host: $serverDistance")
            
            val censorDistance = identifyCensorHop(target, port, serverDistance, vpnService)
            
            val finalTtl = if (censorDistance != -1) {
                censorDistance 
            } else {
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

    suspend fun probeUdpDistance(addr: InetAddress, port: Int, vpnService: VpnService?): Int {
        val coarseTtls = listOf(4, 8, 12, 16, 20, 24, 32, 64)
        for (ttl in coarseTtls) {
            if (tryUdpConnect(addr, port, ttl, vpnService)) return ttl
        }
        return 64
    }

    private suspend fun tryUdpConnect(addr: InetAddress, port: Int, ttl: Int, vpnService: VpnService?): Boolean {
        return withContext(ProxyDispatcher.io) {
            var socket: java.net.DatagramSocket? = null
            try {
                socket = java.net.DatagramSocket()
                vpnService?.protect(socket)
                TtlHelper.setUdpTtl(socket, ttl, addr is java.net.Inet6Address)
                socket.soTimeout = 1000
                val data = if (port == 53) DnsPacketEngine.buildDnsQuery("google.com", 1, 123) else ByteArray(16)
                socket.send(java.net.DatagramPacket(data, data.size, addr, port))
                val buffer = ByteArray(512)
                socket.receive(java.net.DatagramPacket(buffer, buffer.size))
                true
            } catch (e: Throwable) {
                false
            } finally {
                try { socket?.close() } catch (e: Throwable) {}
            }
        }
    }

    private fun updateGlobalConsensus(newTtl: Int) {
        val netType = BypassConfig.getNetworkType().toString()
        val netMap = networkTtls.getOrPut(netType) { ConcurrentHashMap() }
        val currentGlobal = netMap["global"] ?: 0
        if (currentGlobal == 0) {
            netMap["global"] = newTtl
        } else {
            netMap["global"] = (currentGlobal * 0.7 + newTtl * 0.3).toInt().coerceIn(2, 30)
        }
        netMap["global"]?.let { globalTtl ->
            discoveredTtls["global"] = globalTtl
        } ?: run {
            discoveredTtls["global"] = newTtl
        }
    }

    private suspend fun identifyCensorHop(addr: InetAddress, port: Int, serverDist: Int, vpnService: VpnService?): Int = coroutineScope {
        // Parallelized probing for faster results
        // We probe in chunks of 4 TTL values
        val chunkSize = 4
        for (baseTtl in 2 until serverDist step chunkSize) {
            val endTtl = minOf(baseTtl + chunkSize, serverDist)
            val ttls = (baseTtl until endTtl).toList()
            
            val results = ttls.map { ttl ->
                async { if (isCensorTriggered(addr, port, ttl, vpnService)) ttl else -1 }
            }.awaitAll()
            
            val firstTriggered = results.filter { it != -1 }.minOrNull()
            if (firstTriggered != null) return@coroutineScope firstTriggered
        }
        -1
    }

    private suspend fun isCensorTriggered(addr: InetAddress, port: Int, ttl: Int, vpnService: VpnService?): Boolean {
        return withContext(ProxyDispatcher.io) {
            repeat(2) { // Double check to avoid false negatives due to packet loss
                var socket: Socket? = null
                try {
                    socket = Socket()
                    vpnService?.protect(socket)
                    TtlHelper.setTtl(socket, ttl)
                    socket.connect(InetSocketAddress(addr, port), 800)
                    
                    val output = socket.getOutputStream()
                    val input = socket.getInputStream()
                    
                    val rnd = ThreadLocalRandom.current()
                    val trigger = when(rnd.nextInt(3)) {
                        0 -> FakePacketHelper.buildRealisticTlsHello("blocked.com")
                        1 -> "GET / HTTP/1.1\r\nHost: blocked.com\r\n\r\n".toByteArray()
                        else -> FakePacketHelper.buildHttpChaosPacket()
                    }
                    output.write(trigger); output.flush()
                    
                    val buffer = ByteArray(512)
                    socket.soTimeout = 600
                    val read = try { input.read(buffer) } catch(e: Throwable) { -2 }
                    
                    if (read > 0) {
                        val content = String(buffer, 0, read.coerceAtMost(64), Charsets.US_ASCII).lowercase()
                        if (content.contains("forbidden") || content.contains("block") || buffer[0] == 0x15.toByte()) return@withContext true
                        // Any unexpected data at low TTL is suspicious
                        return@withContext true
                    }
                } catch (e: java.net.SocketTimeoutException) {
                    // No response within TTL is normal for non-censor hop
                } catch (e: Throwable) {
                    val msg = e.message?.lowercase() ?: ""
                    if (msg.contains("reset") || msg.contains("closed") || msg.contains("pipe")) return@withContext true
                } finally {
                    try { socket?.close() } catch (e: Throwable) {}
                }
                delay(ThreadLocalRandom.current().nextLong(10, 50))
            }
            false
        }
    }

    private suspend fun estimateDistance(addr: InetAddress, port: Int, vpnService: VpnService?): Int = withContext(ProxyDispatcher.io) {
        coroutineScope {
            val coarseTtls = listOf(4, 8, 12, 16, 20, 24, 28, 32, 40, 48, 64)
            val coarseResults = coarseTtls.map { ttl ->
                async { if (tryConnect(addr, port, ttl, vpnService)) ttl else -1 }
            }.awaitAll()
            
            val upperBound = coarseResults.filter { it != -1 }.minOrNull() ?: return@coroutineScope -1
            
            // Fine-grained search within the range
            val lowerBound = coarseTtls.filter { it < upperBound }.maxOrNull() ?: 1
            val fineTtls = (lowerBound until upperBound).toList()
            val fineResults = fineTtls.map { ttl ->
                async { if (tryConnect(addr, port, ttl, vpnService)) ttl else -1 }
            }.awaitAll()
            
            fineResults.filter { it != -1 }.minOrNull() ?: upperBound
        }
    }

    private suspend fun tryConnect(addr: InetAddress, port: Int, ttl: Int, vpnService: VpnService?): Boolean {
        return withContext(ProxyDispatcher.io) {
            var socket: Socket? = null
            try {
                socket = Socket()
                vpnService?.protect(socket)
                TtlHelper.setTtl(socket, ttl)
                socket.connect(InetSocketAddress(addr, port), 1200)
                true
            } catch (e: Throwable) {
                false
            } finally {
                try { socket?.close() } catch (e: Throwable) {}
            }
        }
    }
}
