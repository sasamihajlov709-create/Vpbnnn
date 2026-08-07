package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom

object TcpRaceConnector {

    data class RaceResult(
        val socket: Socket,
        val input: InputStream,
        val output: OutputStream,
        val firstResponse: ByteArray,
        val firstResponseLen: Int,
        val strategy: BypassStrategy
    )

    suspend fun racingConnect(
        ips: List<java.net.InetAddress>,
        port: Int,
        vpnService: VpnService?,
        host: String,
        strat1: BypassStrategy,
        strat2: BypassStrategy,
        firstPacket: ByteArray,
        firstPacketLen: Int,
        bufferSize: Int
    ): RaceResult? = coroutineScope {
        val resultChannel = Channel<RaceResult>(2)
        
        val job1 = launch(ProxyDispatcher.io) {
            try {
                val res = runSingleAttempt(ips, port, vpnService, host, strat1, firstPacket, firstPacketLen, bufferSize)
                if (res != null) resultChannel.send(res)
            } catch (e: Exception) {
                Log.v("TcpRaceConnector", "Attempt 1 failed for $host with $strat1: ${e.message}")
            }
        }
        
        val job2 = launch(ProxyDispatcher.io) {
            try {
                delay(200) // Priority delay
                val res = runSingleAttempt(ips, port, vpnService, host, strat2, firstPacket, firstPacketLen, bufferSize)
                if (res != null) resultChannel.send(res)
            } catch (e: Exception) {
                Log.v("TcpRaceConnector", "Attempt 2 failed for $host with $strat2: ${e.message}")
            }
        }
        
        var winner: RaceResult? = null
        try {
            winner = withTimeoutOrNull(6000) {
                resultChannel.receive()
            }
        } catch (e: Throwable) {
            Log.v("TcpRaceConnector", "Race timeout for $host")
        } finally {
            job1.cancel()
            job2.cancel()
            
            // Close any losers
            launch(ProxyDispatcher.io) {
                repeat(2) {
                    val other = resultChannel.tryReceive().getOrNull()
                    if (other != null && other.socket != winner?.socket) {
                        try { 
                            other.input.close()
                            other.output.close()
                            other.socket.close() 
                        } catch (e: Throwable) {
                            Log.v("TcpRaceConnector", "Failed to close loser socket: ${e.message}")
                        }
                    }
                }
                resultChannel.close()
            }
        }
        winner
    }

    private suspend fun runSingleAttempt(
        ips: List<java.net.InetAddress>,
        port: Int,
        vpnService: VpnService?,
        host: String,
        strategy: BypassStrategy,
        firstPacket: ByteArray,
        firstPacketLen: Int,
        bufferSize: Int
    ): RaceResult? {
        val config = BypassConfig.getSessionConfig(host, strategy, BypassConfig.currentRttMs.value)
        val rs = TcpTransportManager.connectToBestIp(ips, port, vpnService, config, host) ?: return null
        
        try {
            rs.tcpNoDelay = true
            rs.soTimeout = (BypassConfig.currentRttMs.value * 2 + 1000).coerceAtMost(3000).toInt()
            
            val rsOut = rs.getOutputStream()
            val rsIn = rs.getInputStream()
            
            BypassApplier.applyBypass(rs, rsOut, firstPacket, firstPacketLen, config, host)
            
            val responseBuf = ByteArray(bufferSize)
            val readBytes = withTimeoutOrNull(2500) { rsIn.read(responseBuf) } ?: -1
            
            if (readBytes > 0) {
                DpiEngine.recordResult(strategy, true, HostClassifier.classify(host), host = host)
                BypassConfig.recordSuccess(strategy, 100, host)
                return RaceResult(rs, rsIn, rsOut, responseBuf, readBytes, strategy)
            } else {
                try { rs.close() } catch (e: Throwable) {}
                return null
            }
        } catch (e: Throwable) {
            try { rs.close() } catch (ex: Throwable) {}
            return null
        }
    }
}
