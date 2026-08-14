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
        val effectiveDelay = calculateRttAdaptiveDelay(rtt, config.delay1)

        if (length <= 5) {
            output.write(data, 0, length); output.flush(); return
        }

        try { 
            socket.tcpNoDelay = true 
        } catch (e: java.net.SocketException) {
            android.util.Log.v("BypassApplier", "Failed to set tcpNoDelay: ${e.message}")
        } catch (e: Exception) {
            android.util.Log.v("BypassApplier", "Unexpected error setting tcpNoDelay: ${e.message}")
        }

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
            if (strategy == BypassStrategy.HTTP_MULTI_LINE_MANGLE || strategy == BypassStrategy.BYEBYEDPI_HYBRID || strategy == BypassStrategy.TCP_COMBINED_HYBRID) {
                finalData = EvasionPacketMangler.applyHybridHttpMangle(finalData, finalLen)
                finalLen = finalData.size
            }
        } else if (isProbableTls(data, length)) {
            if (strategy == BypassStrategy.TLS_SESSION_ID_MANGLE || (strategy.family == StrategyFamily.TLS && rnd.nextInt(100) < 15)) {
                finalData = FakePacketHelper.mangleSessionId(finalData, finalLen)
                finalLen = finalData.size
            }
            if (strategy == BypassStrategy.TLS_SNI_JITTER_SPLIT || strategy == BypassStrategy.TLS_SNI_EXT_MANGLE || strategy == BypassStrategy.TLS_EXT_CHAOS || strategy == BypassStrategy.BYEBYEDPI_HYBRID || strategy == BypassStrategy.TCP_COMBINED_HYBRID || strategy == BypassStrategy.BYEBYEDPI_EXTREME) {
                finalData = EvasionPacketMangler.applyHybridTlsMangle(finalData, finalLen, rnd)
                finalLen = finalData.size
            }
        }

        val executorType = StrategyExecutionRegistry.getExecutorType(strategy) ?: when (strategy.family) {
            StrategyFamily.HTTP -> StrategyExecutionRegistry.ExecutorType.HTTP_HANDLER
            StrategyFamily.TLS -> StrategyExecutionRegistry.ExecutorType.TLS_HANDLER
            StrategyFamily.TCP -> StrategyExecutionRegistry.ExecutorType.TCP_BASIC_HANDLER
            StrategyFamily.FRAGMENTATION -> StrategyExecutionRegistry.ExecutorType.FRAGMENTATION_HANDLER
            StrategyFamily.ADAPTIVE -> StrategyExecutionRegistry.ExecutorType.ADAPTIVE_HANDLER
            StrategyFamily.TIMING -> StrategyExecutionRegistry.ExecutorType.TIMING_HANDLER
            else -> StrategyExecutionRegistry.ExecutorType.DIRECT
        }

        when (executorType) {
            StrategyExecutionRegistry.ExecutorType.HTTP_HANDLER -> {
                HttpStrategyHandler.handleHttpStrategies(socket, output, finalData, finalLen, rnd, host, strategy)
            }
            StrategyExecutionRegistry.ExecutorType.TLS_HANDLER -> {
                TlsStrategyHandler.handleTlsStrategies(socket, output, finalData, finalLen, rnd, host, strategy)
            }
            StrategyExecutionRegistry.ExecutorType.TCP_BASIC_HANDLER -> {
                TcpBasicStrategyHandler.handleTcpStrategies(socket, output, finalData, finalLen, rnd, host, strategy)
            }
            StrategyExecutionRegistry.ExecutorType.FRAGMENTATION_HANDLER -> {
                FragmentationStrategyHandler.handleFragmentationStrategies(socket, output, finalData, finalLen, rnd, host, strategy, config, effectiveDelay)
            }
            StrategyExecutionRegistry.ExecutorType.ADAPTIVE_HANDLER -> {
                AdaptiveStrategyHandler.handleAdaptiveStrategies(socket, output, finalData, finalLen, rnd, host, strategy, config)
            }
            StrategyExecutionRegistry.ExecutorType.TIMING_HANDLER -> {
                TimingStrategyHandler.handleTimingStrategies(socket, output, finalData, finalLen, rnd, host, strategy)
            }
            StrategyExecutionRegistry.ExecutorType.DIRECT,
            StrategyExecutionRegistry.ExecutorType.DNS_OVER_TCP,
            StrategyExecutionRegistry.ExecutorType.DNS_OVER_QUIC,
            StrategyExecutionRegistry.ExecutorType.UDP_HANDLER -> {
                output.write(finalData, 0, finalLen)
                output.flush()
            }
        }
    }

    suspend fun applyUdpBypass(socket: DatagramSocket, packet: DatagramPacket, config: SessionConfig, host: String) {
        val rnd = ThreadLocalRandom.current()
        val strategy = config.strategy
        if (strategy == BypassStrategy.DIRECT) {
            socket.send(packet); return
        }
        val data = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
        UdpStrategyHandler.handleUdpStrategies(
            socket, packet.address, packet.port, data, packet.length, rnd, host, strategy
        )
    }

    fun recordStrategyResult(host: String, strategy: BypassStrategy, success: Boolean, avgDuration: Long = 50L) {
        if (success) {
            BypassConfig.recordSuccess(strategy, avgDuration, host)
        } else {
            BypassConfig.recordFailure(strategy, host)
        }
    }

    fun isProbableHttp(data: ByteArray, length: Int): Boolean {
        if (length < 8) return false
        return HttpParser.isHttpRequest(data, length)
    }

    fun isProbableTls(data: ByteArray, length: Int): Boolean {
        if (length < 5) return false
        // TLS Record Layer: 0x16 (Handshake), 0x03 (Version major 3), version minor 0..4
        val major = data[1].toInt() and 0xFF
        val minor = data[2].toInt() and 0xFF
        return data[0] == 0x16.toByte() && major == 3 && minor in 0..4
    }

    fun findHeaderEnd(data: ByteArray, length: Int): Int {
        for (i in 0..length - 4) {
            if (data[i] == '\r'.code.toByte() && data[i+1] == '\n'.code.toByte() &&
                data[i+2] == '\r'.code.toByte() && data[i+3] == '\n'.code.toByte()) return i + 4
        }
        return -1
    }

    fun calculateRttAdaptiveDelay(rttMs: Long, customDelay: Long = 0L, minMs: Long = 2L, maxMs: Long = 80L): Long {
        if (customDelay > 0) return customDelay
        val proportional = (rttMs * 0.10).toLong()
        val rndOffset = ThreadLocalRandom.current().nextLong(0, 3)
        return (proportional + rndOffset).coerceIn(minMs, maxMs)
    }
}
