package com.aistudio.pinkproxy.fresh

import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom

/**
 * Context and parameters required for executing a TCP-based DPI bypass strategy.
 */
data class TcpExecutionContext(
    val socket: Socket,
    val output: OutputStream,
    val data: ByteArray,
    val length: Int,
    val host: String,
    val strategy: BypassStrategy,
    val config: SessionConfig,
    val effectiveDelayMs: Long,
    val random: ThreadLocalRandom = ThreadLocalRandom.current(),
    val isFirstPacket: Boolean = true
)

/**
 * Context and parameters required for executing a UDP-based DPI bypass strategy.
 */
data class UdpExecutionContext(
    val socket: DatagramSocket,
    val address: InetAddress,
    val port: Int,
    val data: ByteArray,
    val length: Int,
    val host: String,
    val strategy: BypassStrategy,
    val config: SessionConfig,
    val random: ThreadLocalRandom = ThreadLocalRandom.current(),
    val isFirstPacket: Boolean = true
)

class UnsupportedStrategyException(
    val strategy: BypassStrategy,
    val executorType: StrategyExecutionRegistry.ExecutorType
) : RuntimeException("Strategy $strategy is not supported by executor $executorType")

/**
 * Strict industrial interface for strategy executors in PinkProxy DPI bypass pipeline.
 */
interface StrategyExecutor {
    /**
     * Unique identifier matching StrategyExecutionRegistry.ExecutorType.
     */
    val executorType: StrategyExecutionRegistry.ExecutorType

    /**
     * Supported transports for this executor implementation.
     */
    val supportedTransports: Set<TransportType>

    /**
     * Executes TCP DPI bypass strategy. Throws UnsupportedStrategyException if not implemented.
     */
    suspend fun executeTcp(context: TcpExecutionContext) {
        throw UnsupportedStrategyException(context.strategy, executorType)
    }

    /**
     * Executes UDP DPI bypass strategy. Throws UnsupportedStrategyException if not implemented.
     */
    suspend fun executeUdp(context: UdpExecutionContext) {
        throw UnsupportedStrategyException(context.strategy, executorType)
    }

    /**
     * Checks if this executor explicitly supports the given strategy.
     */
    fun supportsStrategy(strategy: BypassStrategy): Boolean
}
