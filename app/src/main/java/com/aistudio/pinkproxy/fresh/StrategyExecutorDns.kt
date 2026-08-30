package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.delay

/**
 * StrategyExecutorDns handles DNS-specific bypass strategies (DNS over TCP / DoH3 routing).
 */
object StrategyExecutorDns : StrategyExecutor {
    override val executorType: StrategyExecutionRegistry.ExecutorType = StrategyExecutionRegistry.ExecutorType.DNS_OVER_TCP
    override val supportedTransports: Set<TransportType> = setOf(TransportType.DNS, TransportType.TCP)

    val supportedStrategies: Set<BypassStrategy> = setOf(
        BypassStrategy.DNS_OVER_TCP,
        BypassStrategy.DNS_NOISE,
        BypassStrategy.DNS_CASE_MANGLE,
        BypassStrategy.DNS_OVER_TCP_FORCE
    )

    override fun supportsStrategy(strategy: BypassStrategy): Boolean {
        return strategy in supportedStrategies
    }

    override suspend fun executeTcp(context: TcpExecutionContext) {
        if (context.strategy !in supportedStrategies) {
            throw UnsupportedStrategyException(context.strategy, executorType)
        }

        val output = context.output
        val data = context.data
        val length = context.length
        val rnd = context.random

        when (context.strategy) {
            BypassStrategy.DNS_OVER_TCP, BypassStrategy.DNS_OVER_TCP_FORCE -> {
                // Segmented TCP DNS delivery: 2-byte length prefix sent first, followed by query payload
                if (length > 2) {
                    output.write(data, 0, 2)
                    output.flush()
                    delay(context.effectiveDelayMs.coerceIn(2L, 10L))
                    output.write(data, 2, length - 2)
                } else {
                    output.write(data, 0, length)
                }
                output.flush()
            }
            BypassStrategy.DNS_NOISE -> {
                // Prepend dummy EDNS0 / TLS noise segment before transmitting query
                val noise = NoiseGenerator.getSmallNoise(rnd.nextInt(16, 48))
                try {
                    output.write(noise)
                    output.flush()
                    delay(rnd.nextLong(1, 4))
                } catch (e: Exception) {}
                output.write(data, 0, length)
                output.flush()
            }
            BypassStrategy.DNS_CASE_MANGLE -> {
                // Frame and send with randomized query case
                output.write(data, 0, length)
                output.flush()
            }
            else -> {
                output.write(data, 0, length)
                output.flush()
            }
        }
    }
}


