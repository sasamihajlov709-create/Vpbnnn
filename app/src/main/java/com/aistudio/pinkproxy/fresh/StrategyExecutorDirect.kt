package com.aistudio.pinkproxy.fresh

import java.io.IOException

/**
 * StrategyExecutorDirect handles pass-through DIRECT strategy and BLOCK_TRAFFIC policy.
 */
object StrategyExecutorDirect : StrategyExecutor {

    override val executorType: StrategyExecutionRegistry.ExecutorType = StrategyExecutionRegistry.ExecutorType.DIRECT
    override val supportedTransports: Set<TransportType> = setOf(TransportType.TCP, TransportType.UDP, TransportType.DNS)

    val supportedStrategies: Set<BypassStrategy> = setOf(
        BypassStrategy.DIRECT,
        BypassStrategy.BLOCK_TRAFFIC
    )

    override fun supportsStrategy(strategy: BypassStrategy): Boolean {
        return strategy in supportedStrategies
    }

    override suspend fun executeTcp(context: TcpExecutionContext) {
        if (context.strategy == BypassStrategy.BLOCK_TRAFFIC) {
            throw IOException("Traffic explicitly blocked by policy")
        }
        context.output.write(context.data, 0, context.length)
        context.output.flush()
    }

    override suspend fun executeUdp(context: UdpExecutionContext) {
        if (context.strategy == BypassStrategy.BLOCK_TRAFFIC) {
            return // Silently drop UDP packet
        }
        val packet = java.net.DatagramPacket(context.data, context.length, context.address, context.port)
        context.socket.send(packet)
    }
}
