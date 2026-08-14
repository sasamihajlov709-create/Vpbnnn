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
    val random: ThreadLocalRandom = ThreadLocalRandom.current()
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
    val random: ThreadLocalRandom = ThreadLocalRandom.current()
)

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
     * Executes TCP DPI bypass strategy. Default implementation passes through payload.
     */
    suspend fun executeTcp(context: TcpExecutionContext) {
        context.output.write(context.data, 0, context.length)
        context.output.flush()
    }

    /**
     * Executes UDP DPI bypass strategy. Default implementation passes through packet.
     */
    suspend fun executeUdp(context: UdpExecutionContext) {
        val packet = DatagramPacket(context.data, context.length, context.address, context.port)
        context.socket.send(packet)
    }

    /**
     * Checks if this executor explicitly supports the given strategy.
     */
    fun supportsStrategy(strategy: BypassStrategy): Boolean
}
