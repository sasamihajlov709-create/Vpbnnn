package com.aistudio.pinkproxy.fresh

import java.io.OutputStream
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom
import kotlinx.coroutines.delay

object FragmentationStrategyHandler {
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

        if (strategy == BypassStrategy.TCP_PULSE_FRAG) {
            // Pulse fragmentation: burst small chunk, micro-delay, burst medium chunk
            var pos = 0
            while (pos < length) {
                val burst = rnd.nextInt(2, 8).coerceAtMost(length - pos)
                output.write(data, pos, burst)
                output.flush()
                pos += burst
                if (pos < length) delay(rnd.nextLong(2, 10))
            }
            return
        }

        if (strategy == BypassStrategy.SNI_SPLIT || strategy == BypassStrategy.SNI_TRIPLE || 
            strategy == BypassStrategy.TLS_SNI_FRAGMENT || strategy == BypassStrategy.TLS_SNI_SPLIT || 
            strategy == BypassStrategy.TLS_SNI_JITTER_SPLIT || strategy == BypassStrategy.TLS_RECORD_FRAGMENTATION || 
            strategy == BypassStrategy.ECH_FRAG || strategy == BypassStrategy.FRAGMENT_MULTI ||
            strategy == BypassStrategy.TLS_REC_SPLIT) {
            
            if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                val sniPos = TlsParser.findSni(data, length)
                if (sniPos > 0) {
                    val split1 = if (config.frag1 in 1 until length) config.frag1 else (sniPos - rnd.nextInt(1, 3)).coerceIn(1, length - 1)
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
