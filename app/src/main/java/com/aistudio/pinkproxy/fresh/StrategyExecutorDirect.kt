package com.aistudio.pinkproxy.fresh

/**
 * StrategyExecutorDirect handles pass-through DIRECT strategy.
 */
object StrategyExecutorDirect : StrategyExecutor {
    override val executorType: StrategyExecutionRegistry.ExecutorType = StrategyExecutionRegistry.ExecutorType.DIRECT
    override val supportedTransports: Set<TransportType> = setOf(TransportType.TCP, TransportType.UDP, TransportType.DNS)

    val supportedStrategies: Set<BypassStrategy> = setOf(
        BypassStrategy.DIRECT
    )

    override fun supportsStrategy(strategy: BypassStrategy): Boolean {
        return strategy in supportedStrategies
    }

    override suspend fun executeTcp(context: TcpExecutionContext) {
        context.output.write(context.data, 0, context.length)
        context.output.flush()
    }

    override suspend fun executeUdp(context: UdpExecutionContext) {
        val packet = java.net.DatagramPacket(context.data, context.length, context.address, context.port)
        context.socket.send(packet)
    }
}
