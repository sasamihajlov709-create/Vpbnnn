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
        FragmentationStrategyHandler.handleFragmentationStrategies(socket, output, data, length, rnd, host, strategy, effectiveDelay)
    }

    suspend fun handleAdaptiveStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy, config: SessionConfig) {
        AdaptiveStrategyHandler.handleAdaptiveStrategies(socket, output, data, length, rnd, host, strategy, config)
    }

    suspend fun handleTimingStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy) {
        TimingStrategyHandler.handleTimingStrategies(socket, output, data, length, rnd, host, strategy)
    }
}
