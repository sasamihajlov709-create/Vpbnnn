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
            val isMobile = NetworkProfileManager.currentProfile.value.id.startsWith("mobile")
            if (isMobile) {
                // Adaptive buffering for cellular connections: prevents ACK throttling & queue starvation
                socket.receiveBufferSize = 128 * 1024
                socket.sendBufferSize = 64 * 1024
            } else {
                socket.receiveBufferSize = 65536
                socket.sendBufferSize = 65536
            }
        } catch (e: Exception) {
            Log.v("TcpTransportManager", "Failed to configure socket: ${e.message}")
        } catch (e: Throwable) {
             // Critical errors or OOM, just log and continue if possible
             Log.e("TcpTransportManager", "Critical socket configuration error", e)
        }
    }

    suspend fun performSniGhosting(decoy: String, vpnService: VpnService?) {
        var s: Socket? = null
        try {
            s = Socket()
            vpnService?.protect(s)
            val resolved = RobustResolver.resolveDual(decoy, vpnService)
            if (resolved.isNotEmpty()) {
                s.connect(InetSocketAddress(resolved.random(), 443), 2000)
                val out = s.getOutputStream()
                val hello = FakePacketHelper.buildRealisticTlsHello(decoy)
                
                val discoveredTtl = BypassConfig.fakeTtl.takeIf { it > 0 } ?: AutoTtlProber.getDiscoveredTtl(decoy) ?: 4
                TtlHelper.setTtl(s, discoveredTtl)
                
                out.write(hello)
                out.flush()
                kotlinx.coroutines.delay(10)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.v("TcpTransportManager", "SNI ghosting failed for $decoy: ${e.message}")
        } catch (e: Throwable) {
            Log.e("TcpTransportManager", "Critical SNI ghosting error", e)
        } finally {
            try { s?.close() } catch (ignored: Exception) {}
        }
    }

    fun oscillateWindowSize(socket: Socket) {
        try {
            val rnd = ThreadLocalRandom.current()
            socket.receiveBufferSize = if (rnd.nextBoolean()) 
                rnd.nextInt(256, 1024) 
            else 
                rnd.nextInt(32768, 65536)
        } catch (e: Exception) {
            Log.v("TcpTransportManager", "Window oscillation failed: ${e.message}")
        } catch (e: Throwable) {
            Log.v("TcpTransportManager", "Critical oscillation error: ${e.message}")
        }
    }

    suspend fun applyWindowPulse(socket: Socket) {
        try {
            val original = socket.receiveBufferSize
            oscillateWindowSize(socket)
            kotlinx.coroutines.delay(50)
            socket.receiveBufferSize = original
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.v("TcpTransportManager", "Window pulse failed: ${e.message}")
        } catch (e: Throwable) {
            Log.v("TcpTransportManager", "Critical pulse error: ${e.message}")
        }
    }

    suspend fun connectToBestIp(
        ips: List<java.net.InetAddress>,
        port: Int,
        vpnService: android.net.VpnService?,
        config: SessionConfig,
        host: String
    ): Socket? {
        if (ips.isEmpty()) return null
        return HappyEyeballsConnector.connectHappyEyeballs(ips, port, vpnService, host)
    }
}
