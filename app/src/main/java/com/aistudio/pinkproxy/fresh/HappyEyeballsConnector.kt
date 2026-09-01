package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger

/**
 * High-performance RFC 8305 (Happy Eyeballs v2) Dual-Stack Connection Engine.
 *
 * Implements staggered parallel TCP handshakes between IPv6 and IPv4 addresses with an
 * initial 50-75ms IPv6 head start. If a mobile ISP / TSPU blocks IPv4 routes to target CDNs
 * (e.g. YouTube/Discord/Cloudflare), IPv6 succeeds smoothly without user-noticeable lag (0-50ms).
 */
object HappyEyeballsConnector {

    private const val RESOLUTION_DELAY_MS = 60L // RFC 8305 Section 5 recommendation (50-100ms)

    suspend fun connectHappyEyeballs(
        ips: List<InetAddress>,
        port: Int,
        vpnService: VpnService?,
        host: String,
        timeoutMs: Int = 5000
    ): Socket? = coroutineScope {
        if (ips.isEmpty()) return@coroutineScope null
        if (ips.size == 1) {
            var single: Socket? = null
            try {
                single = ProtectedSocketFactory.createProtectedSocket(vpnService)
                TcpTransportManager.configureSocket(single)
                TtlHelper.tuneSocket(single)
                TtlHelper.applyMssClamping(single, host)
                single.connect(InetSocketAddress(ips[0], port), timeoutMs)
                return@coroutineScope single
            } catch (e: Exception) {
                try { single?.close() } catch (ignored: Exception) {}
                return@coroutineScope null
            }
        }

        val v6Addresses = ips.filterIsInstance<Inet6Address>()
        val v4Addresses = ips.filterIsInstance<Inet4Address>()

        // Interleave addresses according to RFC 8305: [v6_0, v4_0, v6_1, v4_1, ...]
        val interleaved = mutableListOf<Pair<InetAddress, Long>>()
        val maxLen = maxOf(v6Addresses.size, v4Addresses.size)
        var delayAccumulator = 0L

        for (i in 0 until maxLen) {
            if (i < v6Addresses.size) {
                interleaved.add(v6Addresses[i] to delayAccumulator)
                // Give IPv6 a small head start before attempting IPv4
                delayAccumulator += RESOLUTION_DELAY_MS
            }
            if (i < v4Addresses.size) {
                interleaved.add(v4Addresses[i] to delayAccumulator)
                delayAccumulator += RESOLUTION_DELAY_MS
            }
        }

        val candidateList = interleaved.take(6)
        val channel = Channel<Socket>(candidateList.size)
        val completedCount = AtomicInteger(0)

        candidateList.forEach { (ip, initialDelay) ->
            launch(ProxyDispatcher.io) {
                var s: Socket? = null
                try {
                    if (initialDelay > 0) {
                        delay(initialDelay)
                    }
                    s = ProtectedSocketFactory.createProtectedSocket(vpnService)
                    TcpTransportManager.configureSocket(s)
                    TtlHelper.tuneSocket(s)
                    TtlHelper.applyMssClamping(s, host)

                    val connTimeout = if (ip is Inet6Address) timeoutMs else (timeoutMs - initialDelay.toInt()).coerceAtLeast(2000)
                    s.connect(InetSocketAddress(ip, port), connTimeout)

                    if (!channel.trySend(s).isSuccess) {
                        try { s.close() } catch (ignored: Exception) {}
                    }
                } catch (e: CancellationException) {
                    try { s?.close() } catch (ignored: Exception) {}
                    throw e
                } catch (e: Exception) {
                    try { s?.close() } catch (ignored: Exception) {}
                } finally {
                    if (completedCount.incrementAndGet() == candidateList.size) {
                        channel.close()
                    }
                }
            }
        }

        var winningSocket: Socket? = null
        try {
            winningSocket = channel.receiveCatching().getOrNull()
        } catch (e: Exception) {
            Log.v("HappyEyeballs", "Failed to obtain winning dual-stack socket for $host: ${e.message}")
        } finally {
            // Drain and close losing candidate sockets
            launch(ProxyDispatcher.io) {
                while (true) {
                    val remaining = channel.tryReceive().getOrNull() ?: break
                    if (remaining != winningSocket) {
                        try {
                            // SO_LINGER 0 forces immediate TCP RST discarding without lingering in TIME_WAIT
                            remaining.setSoLinger(true, 0)
                        } catch (ignored: Exception) {}
                        try { remaining.close() } catch (ignored: Exception) {}
                    }
                }
            }
        }

        winningSocket
    }
}
