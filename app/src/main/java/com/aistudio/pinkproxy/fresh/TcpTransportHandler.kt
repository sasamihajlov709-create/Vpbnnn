package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom
import kotlinx.coroutines.selects.select

object TcpTransportHandler {

    suspend fun handleTcpSession(
        clientSocket: Socket,
        targetHost: String,
        targetPort: Int,
        vpnService: VpnService?,
        scope: CoroutineScope
    ) {
        var remoteSocket: Socket? = null
        ProxyStats.updateConnections(1)
        try {
            val resolved = RobustResolver.resolve(targetHost, vpnService)
            if (resolved.isEmpty()) {
                Log.w("TcpTransport", "Resolution failed for $targetHost")
                clientSocket.close()
                return
            }
            ProxyStats.addTraffic(targetHost)

            val strategy = BypassConfig.getBestStrategyForHost(targetHost)
            val config = BypassConfig.getSessionConfig(targetHost, strategy, BypassConfig.currentRttMs.value)

            remoteSocket = Socket()
            vpnService?.protect(remoteSocket)
            
            val start = System.currentTimeMillis()
            withTimeout(10000) {
                remoteSocket.connect(InetSocketAddress(resolved.first(), targetPort), 5000)
            }
            val connectTime = System.currentTimeMillis() - start
            BypassConfig.TrafficShaper.updateRtt(connectTime)

            val clientIn = clientSocket.getInputStream()
            val clientOut = clientSocket.getOutputStream()
            val remoteIn = remoteSocket.getInputStream()
            val remoteOut = remoteSocket.getOutputStream()

            coroutineScope {
                // Forward from Remote to Client (Direct)
                val remoteToClient = launch(Dispatchers.IO) {
                    val buffer = ProxyStats.obtain64k()
                    try {
                        var n: Int
                        while (remoteIn.read(buffer).also { n = it } != -1) {
                            clientOut.write(buffer, 0, n)
                            clientOut.flush()
                            ProxyStats.updateBytes(n.toLong())
                        }
                    } catch (e: Exception) {
                    } finally {
                        ProxyStats.release64k(buffer)
                        try { clientSocket.close() } catch (e: Exception) {}
                    }
                }

                // Forward from Client to Remote (with Bypass)
                val clientToRemote = launch(Dispatchers.IO) {
                    val buffer = ProxyStats.obtain64k()
                    try {
                        var n: Int
                        var firstPacket = true
                        while (clientIn.read(buffer).also { n = it } != -1) {
                            if (firstPacket) {
                                firstPacket = false
                                val startBypass = System.currentTimeMillis()
                                try {
                                    BypassConfig.applyBypass(remoteSocket!!, remoteOut, buffer, n, config, targetHost)
                                    BypassConfig.recordSuccess(strategy, System.currentTimeMillis() - startBypass, targetHost)
                                } catch (e: Exception) {
                                    BypassConfig.recordFailure(strategy, targetHost)
                                    throw e
                                }
                            } else {
                                remoteOut.write(buffer, 0, n)
                                remoteOut.flush()
                            }
                            ProxyStats.updateBytes(n.toLong())
                        }
                    } catch (e: Exception) {
                        BypassConfig.TrafficShaper.recordError()
                    } finally {
                        ProxyStats.release64k(buffer)
                        try { remoteSocket?.close() } catch (e: Exception) {}
                    }
                }

                select<Unit> {
                    remoteToClient.onJoin {}
                    clientToRemote.onJoin {}
                }
                
                remoteToClient.cancel()
                clientToRemote.cancel()
            }
        } catch (e: Exception) {
            Log.v("TcpTransport", "Session $targetHost:$targetPort failed: ${e.message}")
        } finally {
            ProxyStats.updateConnections(-1)
            try { clientSocket.close() } catch (e: Exception) {}
            try { remoteSocket?.close() } catch (e: Exception) {}
        }
    }
}
