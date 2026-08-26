package com.aistudio.pinkproxy.fresh

import java.io.OutputStream
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom
import kotlinx.coroutines.delay

object FragmentationStrategyHandler : StrategyExecutor {
    override val executorType: StrategyExecutionRegistry.ExecutorType = StrategyExecutionRegistry.ExecutorType.FRAGMENTATION_HANDLER
    override val supportedTransports: Set<TransportType> = setOf(TransportType.TCP)

    val supportedStrategies: Set<BypassStrategy> = setOf(
        BypassStrategy.SNI_SPLIT,
        BypassStrategy.SNI_TRIPLE,
        BypassStrategy.FRAGMENT_MULTI,
        BypassStrategy.TLS_REC_SPLIT,
        BypassStrategy.TLS_MULTI_FRAG,
        BypassStrategy.TCP_SMALL_CHUNKS,
        BypassStrategy.TCP_REARRANGE_CHUNKS,
        BypassStrategy.TCP_BYTE_FRAG,
        BypassStrategy.TLS_SNI_FRAGMENT,
        BypassStrategy.TCP_PULSE_FRAG
    )

    override fun supportsStrategy(strategy: BypassStrategy): Boolean {
        return strategy in supportedStrategies
    }

    override suspend fun executeTcp(context: TcpExecutionContext) {
        if (context.strategy !in supportedStrategies) {
            throw UnsupportedStrategyException(context.strategy, executorType)
        }
        handleFragmentationStrategies(
            socket = context.socket,
            output = context.output,
            data = context.data,
            length = context.length,
            rnd = context.random,
            host = context.host,
            strategy = context.strategy,
            config = context.config,
            effectiveDelay = context.effectiveDelayMs
        )
    }

    suspend fun handleFragmentationStrategies(
        socket: Socket,
        output: OutputStream,
        data: ByteArray,
        length: Int,
        rnd: ThreadLocalRandom,
        host: String,
        strategy: BypassStrategy,
        config: SessionConfig,
        effectiveDelay: Long
    ) {
        if (strategy == BypassStrategy.TCP_PULSE_FRAG) {
            var pos = 0
            var pulseIndex = 0
            while (pos < length) {
                val sz = if (pulseIndex % 2 == 0) rnd.nextInt(1, 4).coerceAtMost(length - pos) else rnd.nextInt(16, 64).coerceAtMost(length - pos)
                output.write(data, pos, sz)
                output.flush()
                pos += sz
                pulseIndex++
                if (pos < length) {
                    val pulseDelay = if (pulseIndex % 2 == 0) rnd.nextLong(15, 35) else rnd.nextLong(2, 8)
                    delay(pulseDelay)
                }
            }
            return
        }

        if (strategy == BypassStrategy.TCP_BYTE_FRAG) {
            var pos = 0
            while (pos < length) {
                output.write(data, pos, 1)
                output.flush()
                pos += 1
                if (pos < length) delay(effectiveDelay.coerceAtLeast(1L))
            }
            return
        }

        if (strategy == BypassStrategy.TCP_SMALL_CHUNKS) {
            var pos = 0
            while (pos < length) {
                val sz = rnd.nextInt(2, 16).coerceAtMost(length - pos)
                output.write(data, pos, sz)
                output.flush()
                pos += sz
                if (pos < length) delay(rnd.nextLong(1, 4))
            }
            return
        }

        if (strategy == BypassStrategy.TCP_REARRANGE_CHUNKS) {
            if (length > 30) {
                val split1 = length / 3
                val split2 = (length * 2) / 3
                // Send first chunk (header / start)
                output.write(data, 0, split1)
                output.flush()
                delay(rnd.nextLong(2, 6))
                
                // Send middle chunk
                output.write(data, split1, split2 - split1)
                output.flush()
                delay(rnd.nextLong(1, 4))
                
                // Send tail chunk
                output.write(data, split2, length - split2)
                output.flush()
            } else {
                val split = length / 2
                output.write(data, 0, split)
                output.flush()
                delay(rnd.nextLong(1, 3))
                output.write(data, split, length - split)
                output.flush()
            }
            return
        }

        if (strategy == BypassStrategy.TLS_MULTI_FRAG) {
            if (length > 44 && data[0] == 0x16.toByte()) {
                val split = (length / 3).coerceIn(1, length - 6)
                val records = EvasionPacketMangler.splitIntoTlsRecords(data, length, split)
                for (rec in records) {
                    output.write(rec)
                    output.flush()
                    delay(rnd.nextLong(1, 4))
                }
                return
            }
        }

        if (strategy == BypassStrategy.SNI_SPLIT || strategy == BypassStrategy.SNI_TRIPLE || 
            strategy == BypassStrategy.TLS_SNI_FRAGMENT || strategy == BypassStrategy.TLS_SNI_SPLIT || 
            strategy == BypassStrategy.TLS_SNI_JITTER_SPLIT || strategy == BypassStrategy.TLS_RECORD_FRAGMENTATION || 
            strategy == BypassStrategy.ECH_FRAG || strategy == BypassStrategy.FRAGMENT_MULTI ||
            strategy == BypassStrategy.TLS_REC_SPLIT) {
            
            if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                val sniPos = TlsParser.findSni(data, length)
                if (sniPos > 0) {
                    // Smart SNI Split: Target the middle of the SNI domain name to break DPI signature matching
                    val split1 = if (config.frag1 in 1 until length) config.frag1 else {
                        // sniPos points to the first character of the hostname. Let's slice right into the middle of the domain.
                        (sniPos + rnd.nextInt(2, 6)).coerceIn(1, length - 1)
                    }
                    if (split1 > 0) {
                        output.write(data, 0, split1)
                        output.flush()
                        val delayVal = if (strategy == BypassStrategy.TLS_SNI_JITTER_SPLIT) rnd.nextLong(10, 50) else effectiveDelay.coerceAtLeast(1L)
                        delay(delayVal)
                        
                        if (strategy == BypassStrategy.SNI_TRIPLE || strategy == BypassStrategy.FRAGMENT_MULTI) {
                            val split2 = if (config.frag2 > split1 && config.frag2 < length) config.frag2 else (split1 + rnd.nextInt(2, 6)).coerceIn(split1 + 1, length - 1)
                            output.write(data, split1, split2 - split1)
                            output.flush()
                            delay(effectiveDelay.coerceAtLeast(1L))

                            if (config.frag3 > split2 && config.frag3 < length) {
                                val split3 = config.frag3
                                output.write(data, split2, split3 - split2)
                                output.flush()
                                delay(effectiveDelay.coerceAtLeast(1L))
                                output.write(data, split3, length - split3)
                            } else {
                                output.write(data, split2, length - split2)
                            }
                        } else {
                            output.write(data, split1, length - split1)
                        }
                        output.flush()
                        return
                    }
                }
            }
        }

        // Default fragmentation
        var pos = 0
        while (pos < length) {
            val sz = rnd.nextInt(5, 64).coerceAtMost(length - pos)
            output.write(data, pos, sz)
            output.flush()
            pos += sz
            if (pos < length) delay(effectiveDelay.coerceAtLeast(1L))
        }
    }
}
