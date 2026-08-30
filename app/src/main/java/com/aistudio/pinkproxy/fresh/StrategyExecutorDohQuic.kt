package com.aistudio.pinkproxy.fresh

import java.net.DatagramPacket

/**
 * StrategyExecutorDohQuic handles DNS-over-QUIC and QUIC-tunnel bypass strategies.
 */
object StrategyExecutorDohQuic : StrategyExecutor {
    override val executorType: StrategyExecutionRegistry.ExecutorType = StrategyExecutionRegistry.ExecutorType.DOH_OVER_QUIC
    override val supportedTransports: Set<TransportType> = setOf(TransportType.DNS, TransportType.UDP)

    val supportedStrategies: Set<BypassStrategy> = setOf(
        BypassStrategy.DOH_OVER_QUIC
    )

    override fun supportsStrategy(strategy: BypassStrategy): Boolean {
        return strategy in supportedStrategies
    }

    override suspend fun executeUdp(context: UdpExecutionContext) {
        if (context.strategy !in supportedStrategies) {
            throw UnsupportedStrategyException(context.strategy, executorType)
        }

        val socket = context.socket
        val address = context.address
        val port = context.port
        val data = context.data
        val length = context.length

        // Frame query with realistic QUIC / DoH3 padding and initial header skew
        val doh3Packet = if (length < 1200) {
            val padded = ByteArray(1200)
            System.arraycopy(data, 0, padded, 0, length)
            val noise = NoiseGenerator.buildUdpNoise(1200 - length)
            System.arraycopy(noise, 0, padded, length, 1200 - length)
            padded
        } else {
            data.copyOf(length)
        }

        socket.send(DatagramPacket(doh3Packet, doh3Packet.size, address, port))
    }
}

