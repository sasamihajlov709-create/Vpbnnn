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

        if (strategy == BypassStrategy.SNI_SPLIT || strategy == BypassStrategy.SNI_TRIPLE || 
            strategy == BypassStrategy.TLS_SNI_FRAGMENT || strategy == BypassStrategy.TLS_SNI_SPLIT || 
            strategy == BypassStrategy.TLS_SNI_JITTER_SPLIT || strategy == BypassStrategy.TLS_RECORD_FRAGMENTATION || 
            strategy == BypassStrategy.ECH_FRAG) {
            
            if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                val sniPos = TlsParser.findSni(data, length)
                if (sniPos > 0) {
                    val split1 = sniPos - rnd.nextInt(1, 3)
                    if (split1 > 0) {
                        output.write(data, 0, split1)
                        output.flush()
                        val delayVal = if (strategy == BypassStrategy.TLS_SNI_JITTER_SPLIT) rnd.nextLong(10, 50) else effectiveDelay.coerceAtLeast(1L)
                        delay(delayVal)
                        
                        if (strategy == BypassStrategy.SNI_TRIPLE) {
                            val split2 = split1 + rnd.nextInt(2, 6).coerceAtMost(length - split1)
                            output.write(data, split1, split2 - split1)
                            output.flush()
                            delay(effectiveDelay.coerceAtLeast(1L))
                            output.write(data, split2, length - split2)
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
