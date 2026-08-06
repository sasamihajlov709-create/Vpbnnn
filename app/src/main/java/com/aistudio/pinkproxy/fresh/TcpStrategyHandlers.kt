package com.aistudio.pinkproxy.fresh

import java.io.OutputStream
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom
import kotlinx.coroutines.delay

object TcpStrategyHandlers {

    suspend fun handleHttpStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy) {
        HttpStrategyHandler.handleHttpStrategies(socket, output, data, length, rnd, host, strategy)
    }

    suspend fun handleTcpStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy) {
        TcpBasicStrategyHandler.handleTcpStrategies(socket, output, data, length, rnd, host, strategy)
    }

    suspend fun handleTlsStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy) {
        TlsStrategyHandler.handleTlsStrategies(socket, output, data, length, rnd, host, strategy)
    }

    suspend fun handleFragmentationStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy, effectiveDelay: Long) {
        when (strategy) {
            BypassStrategy.TCP_BYTE_FRAG -> {
                var pos = 0
                while (pos < length) {
                    output.write(data, pos, 1)
                    output.flush()
                    pos += 1
                    if (pos < length) delay(effectiveDelay.coerceAtLeast(1L))
                }
            }
            else -> {
                var pos = 0
                while (pos < length) {
                    val sz = rnd.nextInt(5, 32).coerceAtMost(length - pos)
                    output.write(data, pos, sz)
                    output.flush()
                    pos += sz
                    if (pos < length) delay(effectiveDelay.coerceAtLeast(1L))
                }
            }
        }
    }

    suspend fun handleAdaptiveStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy, config: SessionConfig) {
        AdaptiveStrategyHandler.handleAdaptiveStrategies(socket, output, data, length, rnd, host, strategy, config)
    }

    suspend fun handleTimingStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy) {
        if (strategy == BypassStrategy.SLOW_SEND) {
            var pos = 0
            while (pos < length) {
                val sz = rnd.nextInt(1, 3).coerceAtMost(length - pos)
                output.write(data, pos, sz)
                output.flush()
                pos += sz
                if (pos < length) delay(rnd.nextLong(10, 30))
            }
            return
        }

        if (strategy == BypassStrategy.TCP_ACK_DELAY) {
            val part = (length / 4).coerceAtLeast(1)
            output.write(data, 0, part)
            output.flush()
            delay(rnd.nextLong(30, 80))
            output.write(data, part, length - part)
            output.flush()
            return
        }

        var pos = 0
        while (pos < length) {
            val sz = rnd.nextInt(4, 16).coerceAtMost(length - pos)
            output.write(data, pos, sz)
            output.flush()
            pos += sz
            if (pos < length) delay(rnd.nextLong(5, 15))
        }
    }
}
