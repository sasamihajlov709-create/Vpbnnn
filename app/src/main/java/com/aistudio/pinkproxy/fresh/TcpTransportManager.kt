package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom

object TcpTransportManager {

    fun configureSocket(socket: Socket) {
        try {
            socket.tcpNoDelay = true
            socket.keepAlive = true
            socket.receiveBufferSize = 65536
            socket.sendBufferSize = 65536
        } catch (e: Throwable) {
            Log.v("TcpTransportManager", "Failed to configure socket: ${e.message}")
        }
    }

    suspend fun performSniGhosting(decoy: String, vpnService: VpnService?) {
        try {
            val s = Socket()
            vpnService?.protect(s)
            val resolved = RobustResolver.resolve(decoy, vpnService)
            if (resolved.isNotEmpty()) {
                s.connect(InetSocketAddress(resolved.random(), 443), 2000)
                val out = s.getOutputStream()
                val hello = FakePacketHelper.buildRealisticTlsHello(decoy)
                
                val discoveredTtl = BypassConfig.fakeTtl.takeIf { it > 0 } ?: AutoTtlProber.getDiscoveredTtl(decoy) ?: 4
                TtlHelper.setTtl(s, discoveredTtl)
                
                out.write(hello)
                out.flush()
                kotlinx.coroutines.delay(10)
                s.close()
            }
        } catch (e: Throwable) {
            Log.v("TcpTransportManager", "SNI ghosting failed for $decoy: ${e.message}")
        }
    }

    fun oscillateWindowSize(socket: Socket) {
        try {
            val rnd = ThreadLocalRandom.current()
            socket.receiveBufferSize = if (rnd.nextBoolean()) 
                rnd.nextInt(256, 1024) 
            else 
                rnd.nextInt(32768, 65536)
        } catch (e: Throwable) {
            Log.v("TcpTransportManager", "Window oscillation failed: ${e.message}")
        }
    }

    suspend fun applyWindowPulse(socket: Socket) {
        try {
            val original = socket.receiveBufferSize
            oscillateWindowSize(socket)
            kotlinx.coroutines.delay(50)
            socket.receiveBufferSize = original
        } catch (e: Throwable) {
            Log.v("TcpTransportManager", "Window pulse failed: ${e.message}")
        }
    }

    suspend fun connectToBestIp(
        ips: List<java.net.InetAddress>,
        port: Int,
        vpnService: android.net.VpnService?,
        config: SessionConfig,
        host: String
    ): Socket? = kotlinx.coroutines.coroutineScope {
        if (ips.isEmpty()) return@coroutineScope null
        if (ips.size == 1) {
            val s = Socket()
            try {
                vpnService?.protect(s)
                TtlHelper.tuneSocket(s)
                TtlHelper.applyMssClamping(s, host)
                s.connect(java.net.InetSocketAddress(ips[0], port), 5000)
                return@coroutineScope s
            } catch (e: Throwable) {
                try { s.close() } catch (ex: Throwable) {}
                return@coroutineScope null
            }
        }

        val intensity = ProxyStats.censorshipIntensity.value
        val sortedIps = if (intensity > 70) {
            ips.sortedByDescending { it is java.net.Inet6Address }
        } else {
            ips
        }

        val targetIps = sortedIps.take(8)
        val channel = kotlinx.coroutines.channels.Channel<Socket>(targetIps.size)
        val jobs = mutableListOf<kotlinx.coroutines.Job>()
        val completedCount = java.util.concurrent.atomic.AtomicInteger(0)
        
        targetIps.forEachIndexed { index, ip ->
            jobs += launch(ProxyDispatcher.io) {
                val s = Socket()
                try {
                    if (index > 0) kotlinx.coroutines.delay(index * 200L)
                    vpnService?.protect(s)
                    TtlHelper.tuneSocket(s)
                    TtlHelper.applyMssClamping(s, host)
                    
                    val timeout = if (index < 2) 4000 else 7000
                    s.connect(java.net.InetSocketAddress(ip, port), timeout)
                    
                    if (!channel.trySend(s).isSuccess) {
                        try { s.close() } catch (ex: Throwable) {}
                    }
                } catch (e: Throwable) {
                    try { s.close() } catch (ex: Throwable) {}
                } finally {
                    if (completedCount.incrementAndGet() == targetIps.size) {
                        channel.close()
                    }
                }
            }
        }
        
        var result: Socket? = null
        try {
            result = kotlinx.coroutines.withTimeoutOrNull(10000) { channel.receive() }
        } catch (e: Throwable) {
            Log.w("TcpTransportManager", "Racing failed for $host: ${e.message}")
        } finally {
            jobs.forEach { it.cancel() }
            channel.close()
            while (true) {
                val s = channel.tryReceive().getOrNull() ?: break
                try { s.close() } catch (e: Throwable) {
                    Log.v("TcpTransportManager", "Failed to close ghost socket: ${e.message}")
                }
            }
        }
        result
    }
}
