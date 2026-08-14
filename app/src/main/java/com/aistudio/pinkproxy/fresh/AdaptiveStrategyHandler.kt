package com.aistudio.pinkproxy.fresh

import java.io.OutputStream
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom
import kotlinx.coroutines.delay

object AdaptiveStrategyHandler : StrategyExecutor {
    override val executorType: StrategyExecutionRegistry.ExecutorType = StrategyExecutionRegistry.ExecutorType.ADAPTIVE_HANDLER
    override val supportedTransports: Set<TransportType> = setOf(TransportType.TCP, TransportType.UDP)

    override fun supportsStrategy(strategy: BypassStrategy): Boolean {
        return StrategyExecutionRegistry.getExecutorType(strategy) == executorType
    }

    override suspend fun executeTcp(context: TcpExecutionContext) {
        handleAdaptiveStrategies(
            socket = context.socket,
            output = context.output,
            data = context.data,
            length = context.length,
            rnd = context.random,
            host = context.host,
            strategy = context.strategy,
            config = context.config
        )
    }

    override suspend fun executeUdp(context: UdpExecutionContext) {
        UdpStrategyHandler.handleUdpStrategies(
            socket = context.socket,
            address = context.address,
            port = context.port,
            data = context.data,
            length = context.length,
            rnd = context.random,
            host = context.host,
            strategy = context.strategy
        )
    }

    suspend fun handleAdaptiveStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy, config: SessionConfig) {
        when (strategy) {
            BypassStrategy.TCP_COMBINED_NUCLEAR, BypassStrategy.TCP_COMBINED_HYBRID -> {
                handleNuclearStrategy(socket, output, data, length, rnd, host, config)
                return
            }
            BypassStrategy.TLS_0RTT_FAKE -> {
                handleZeroRttSimulation(socket, output, data, length, rnd, host)
                return
            }
            BypassStrategy.BYEBYEDPI_EXTREME, BypassStrategy.BYEBYEDPI_HYBRID -> {
                handleByeByeDpiExtreme(socket, output, data, length, rnd, host, config)
                return
            }
            BypassStrategy.ZAPRET_EXTREME -> {
                CompositePipelineApplier.applyZapretTriplePipeline(socket, output, data, length, host, config, rnd)
                return
            }
            else -> {}
        }
        
        val split1 = (length / 4).coerceAtLeast(1)
        val split2 = (length / 2).coerceAtLeast(split1 + 1)
        if (length > 20) {
            socket.receiveBufferSize = 1
            output.write(data, 0, split1)
            output.flush()
            delay(config.delay1.coerceAtLeast(1L))
            socket.receiveBufferSize = 65536
            output.write(data, split1, split2 - split1)
            output.flush()
            delay(config.delay2.coerceAtLeast(1L))
            output.write(data, split2, length - split2)
            output.flush()
        } else {
            output.write(data, 0, length)
            output.flush()
        }
    }

    private suspend fun handleNuclearStrategy(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, config: SessionConfig) {
        ProxyStats.logTraffic("Triggering NUCLEAR Strategy for $host")
        sendDecoyStorm(socket, output, rnd, host, config)
        
        if (length > 20) {
             val split = length / 3
             output.write(data, 0, split)
             output.flush()
             delay(rnd.nextLong(10, 50))
             output.write(data, split, length - split)
             output.flush()
        } else {
            output.write(data, 0, length)
            output.flush()
        }
    }

    private suspend fun handleZeroRttSimulation(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String) {
        val fake0Rtt = FakePacketHelper.buildRealisticHttp2Header()
        TtlHelper.setTtl(socket, StrategyUtils.getFakeTtl(host, rnd))
        output.write(fake0Rtt)
        output.flush()
        delay(rnd.nextLong(1, 3))
        TtlHelper.setTtl(socket, 64)
        output.write(data, 0, length)
        output.flush()
    }

    private suspend fun sendDecoyStorm(socket: Socket, out: OutputStream, rnd: ThreadLocalRandom, host: String, config: SessionConfig) {
        try {
            val fakeTtl = config.fakeTtl.takeIf { it > 0 } ?: StrategyUtils.getFakeTtl(host, rnd)
            val decoys = listOf(
                FakePacketHelper.buildRealisticHttp2Header(),
                FakePacketHelper.buildRealisticTlsHello("blocked.content.internal"),
                FakePacketHelper.buildHttpChaosPacket(),
                FakePacketHelper.buildStunBindingRequest()
            ).shuffled()

            for (decoy in decoys.take(rnd.nextInt(2, 4))) {
                TtlHelper.setTtl(socket, fakeTtl)
                out.write(decoy)
                out.flush()
                delay(rnd.nextLong(1, 4))
            }
            TtlHelper.setTtl(socket, 64)
        } catch (e: Throwable) {}
    }

    private suspend fun handleByeByeDpiExtreme(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, config: SessionConfig) {
        ProxyStats.logTraffic("Triggering ByeByeDPI Extreme for $host")
        val sniPos = TlsParser.findSni(data, length)
        val splitPos = if (sniPos > 0) sniPos else (length / 2).coerceAtLeast(1)
        val fakeTtl = config.fakeTtl.takeIf { it > 0 } ?: StrategyUtils.getFakeTtl(host, rnd)

        // 1. Send fake decoy payload to confuse DPI state tracking
        val fakeDecoy = FakePacketHelper.buildRealisticHttp2Header()
        TtlHelper.setTtl(socket, fakeTtl)
        output.write(fakeDecoy)
        output.flush()
        delay(rnd.nextLong(1, 4))

        // 2. Out-of-order segment desync with low TTL
        TtlHelper.setTtl(socket, fakeTtl)
        output.write(data, splitPos, length - splitPos)
        output.flush()
        delay(rnd.nextLong(2, 8))
        
        // 3. Send original first part with normal TTL
        TtlHelper.setTtl(socket, BypassConfig.currentTtl)
        output.write(data, 0, splitPos)
        output.flush()
        delay(rnd.nextLong(3, 10))
        
        // 4. Send original second part with normal TTL
        output.write(data, splitPos, length - splitPos)
        output.flush()
    }

    private suspend fun handleZapretExtreme(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, config: SessionConfig) {
        ProxyStats.logTraffic("Triggering Zapret Extreme for $host")
        if (TlsParser.isClientHello(data, length)) {
            val fakeTtl = StrategyUtils.getFakeTtl(host, rnd)
            var pos = 0
            while (pos < length) {
                val sz = if (pos == 0) rnd.nextInt(1, 4) else rnd.nextInt(4, 30)
                val chunk = sz.coerceAtMost(length - pos)
                
                // Inject fake packet with scrambled payload to poison middlebox reassembler
                val fakeNoise = FakePacketHelper.getSmallNoise(chunk)
                TtlHelper.setTtl(socket, fakeTtl)
                output.write(fakeNoise)
                output.flush()
                delay(rnd.nextLong(1, 3))

                // Send real payload chunk with normal TTL
                TtlHelper.setTtl(socket, BypassConfig.currentTtl)
                output.write(data, pos, chunk)
                output.flush()
                pos += chunk
            }
        } else {
            output.write(data, 0, length)
            output.flush()
        }
    }
}
