package com.aistudio.pinkproxy.fresh

import java.io.OutputStream
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom
import kotlinx.coroutines.delay

object TimingStrategyHandler : StrategyExecutor {
    override val executorType: StrategyExecutionRegistry.ExecutorType = StrategyExecutionRegistry.ExecutorType.TIMING_HANDLER
    override val supportedTransports: Set<TransportType> = setOf(TransportType.TCP)

    override fun supportsStrategy(strategy: BypassStrategy): Boolean {
        return StrategyExecutionRegistry.getExecutorType(strategy) == executorType
    }

    override suspend fun executeTcp(context: TcpExecutionContext) {
        handleTimingStrategies(
            socket = context.socket,
            output = context.output,
            data = context.data,
            length = context.length,
            rnd = context.random,
            host = context.host,
            strategy = context.strategy
        )
    }

    suspend fun handleTimingStrategies(
        socket: Socket,
        output: OutputStream,
        data: ByteArray,
        length: Int,
        rnd: ThreadLocalRandom,
        host: String,
        strategy: BypassStrategy
    ) {
        if (strategy == BypassStrategy.SLOW_SEND) {
            var pos = 0
            while (pos < length) {
                val sz = rnd.nextInt(1, 3).coerceAtMost(length - pos)
                output.write(data, pos, sz)
                output.flush()
                pos += sz
                if (pos < length) delay(rnd.nextLong(20, 50))
            }
            return
        }

        if (strategy == BypassStrategy.TCP_ACK_DELAY) {
            val part = (length / 4).coerceAtLeast(1)
            output.write(data, 0, part)
            output.flush()
            delay(rnd.nextLong(40, 100))
            output.write(data, part, length - part)
            output.flush()
            return
        }

        // Generic timing jitter
        var pos = 0
        while (pos < length) {
            val sz = rnd.nextInt(8, 32).coerceAtMost(length - pos)
            output.write(data, pos, sz)
            output.flush()
            pos += sz
            if (pos < length) delay(rnd.nextLong(5, 20))
        }
    }
}
