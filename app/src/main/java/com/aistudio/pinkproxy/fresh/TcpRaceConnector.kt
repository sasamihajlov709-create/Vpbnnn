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
                            try { other.socket.setSoLinger(true, 0) } catch (ignored: Exception) {}
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
            val rtt = BypassConfig.currentRttMs.value
            val raceTimeout = (750 + (rtt * 1.5).toInt()).coerceIn(600, 1800)
            rs.soTimeout = raceTimeout
            
            val rsOut = rs.getOutputStream()
            val rsIn = rs.getInputStream()
            
            val startTime = System.currentTimeMillis()
            BypassApplier.applyBypass(rs, rsOut, firstPacket, firstPacketLen, config, host)
            
            val responseBuf = ByteArray(bufferSize)
            val readBytes = withTimeoutOrNull(raceTimeout.toLong()) {
                try {
                    rsIn.read(responseBuf)
                } catch (e: Exception) {
                    -1
                }
            } ?: -1
            
            if (readBytes > 0) {
                val latency = System.currentTimeMillis() - startTime
                DpiEngine.recordStrategyResult(host, strategy, true, latency)
                return RaceResult(rs, rsIn, rsOut, responseBuf, readBytes, strategy)
            } else {
                DpiEngine.recordStrategyResult(host, strategy, false, 0)
                try { rs.close() } catch (e: Throwable) {}
                return null
            }
        } catch (e: Throwable) {
            try { rs.close() } catch (ex: Throwable) {}
            return null
        }
    }
}
