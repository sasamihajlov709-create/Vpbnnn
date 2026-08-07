package com.aistudio.pinkproxy.fresh

import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom

object BypassApplier {

    suspend fun applyBypass(socket: Socket, output: OutputStream, data: ByteArray, length: Int, config: SessionConfig, host: String) {
        val rnd = ThreadLocalRandom.current()
        val strategy = config.strategy
        if (strategy == BypassStrategy.DIRECT) {
            output.write(data, 0, length); output.flush(); return
        }

        val rtt = BypassConfig.currentRttMs.value
        val adaptiveDelay = when {
            rtt < 40 -> rnd.nextLong(1, 2)
            rtt < 120 -> rnd.nextLong(2, 4)
            else -> rnd.nextLong(5, 12)
        }
        val effectiveDelay = if (config.delay1 > 0) config.delay1 else adaptiveDelay

        if (length <= 5) {
            output.write(data, 0, length); output.flush(); return
        }

        try { socket.tcpNoDelay = true } catch (e: Throwable) {}

        var finalData = data
        var finalLen = length
        
        if (isProbableHttp(data, length)) {
            if (strategy == BypassStrategy.HTTP_METHOD_CASE_MANGLE || (strategy.family == StrategyFamily.HTTP && rnd.nextInt(100) < 20)) {
                finalData = FakePacketHelper.mangleHttpMethodCase(finalData, finalLen)
                finalLen = finalData.size
            }
            if (strategy == BypassStrategy.HTTP_HEADER_CASE_CHAOS) {
                finalData = FakePacketHelper.randomizeHeaderCase(finalData, finalLen)
                finalLen = finalData.size
            }
        }

        when (strategy.family) {
            StrategyFamily.HTTP -> TcpStrategyHandlers.handleHttpStrategies(socket, output, finalData, finalLen, rnd, host, strategy)
            StrategyFamily.TLS -> TcpStrategyHandlers.handleTlsStrategies(socket, output, finalData, finalLen, rnd, host, strategy)
            StrategyFamily.TCP -> TcpStrategyHandlers.handleTcpStrategies(socket, output, finalData, finalLen, rnd, host, strategy)
            StrategyFamily.FRAGMENTATION -> TcpStrategyHandlers.handleFragmentationStrategies(socket, output, finalData, finalLen, rnd, host, strategy, effectiveDelay)
            StrategyFamily.ADAPTIVE -> TcpStrategyHandlers.handleAdaptiveStrategies(socket, output, finalData, finalLen, rnd, host, strategy, config)
            StrategyFamily.TIMING -> TcpStrategyHandlers.handleTimingStrategies(socket, output, finalData, finalLen, rnd, host, strategy)
            else -> {
                if (strategy == BypassStrategy.CHAOS) {
                    val picked = listOf(BypassStrategy.SNI_SPLIT, BypassStrategy.TCP_WINDOW_SHRINK, BypassStrategy.FRAGMENT_MULTI).random()
                    applyBypass(socket, output, data, length, config.copy(strategy = picked), host)
                } else {
                    output.write(finalData, 0, finalLen); output.flush()
                }
            }
        }
    }

    suspend fun applyUdpBypass(socket: DatagramSocket, packet: DatagramPacket, config: SessionConfig, host: String) {
        val rnd = ThreadLocalRandom.current()
        val strategy = config.strategy
        if (strategy == BypassStrategy.DIRECT) {
            socket.send(packet); return
        }
        UdpStrategyHandlers.handleUdpStrategies(socket, packet, rnd, host, strategy, config)
    }

    fun recordStrategyResult(host: String, strategy: BypassStrategy, success: Boolean, avgDuration: Long = 50L) {
        if (success) {
            BypassConfig.recordSuccess(strategy, avgDuration, host)
        } else {
            BypassConfig.recordFailure(strategy, host)
        }
    }

    private fun isProbableHttp(data: ByteArray, length: Int): Boolean {
        if (length < 8) return false
        val s = String(data, 0, minOf(length, 16), Charsets.US_ASCII)
        return s.startsWith("GET ") || s.startsWith("POST ") || s.startsWith("HEAD ") || s.startsWith("HTTP/")
    }

    fun findHeaderEnd(data: ByteArray, length: Int): Int {
        for (i in 0..length - 4) {
            if (data[i] == '\r'.code.toByte() && data[i+1] == '\n'.code.toByte() &&
                data[i+2] == '\r'.code.toByte() && data[i+3] == '\n'.code.toByte()) return i + 4
        }
        return -1
    }
}
