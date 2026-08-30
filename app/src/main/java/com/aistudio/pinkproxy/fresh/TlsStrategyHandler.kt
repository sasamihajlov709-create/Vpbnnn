package com.aistudio.pinkproxy.fresh

import java.io.OutputStream
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom
import kotlinx.coroutines.delay

object TlsStrategyHandler : StrategyExecutor {
    override val executorType: StrategyExecutionRegistry.ExecutorType = StrategyExecutionRegistry.ExecutorType.TLS_HANDLER
    override val supportedTransports: Set<TransportType> = setOf(TransportType.TCP)

    val supportedStrategies: Set<BypassStrategy> = setOf(
        BypassStrategy.SNI_MANGLE,
        BypassStrategy.TLS_DIRTY,
        BypassStrategy.TLS_PAD,
        BypassStrategy.TLS_GREASE,
        BypassStrategy.TLS_EXT_SKEW,
        BypassStrategy.TLS_REC_MANGLE,
        BypassStrategy.TLS_PADDING_RAND,
        BypassStrategy.TLS_REHANDSHAKE_FAKE,
        BypassStrategy.TLS_SNI_SKEW,
        BypassStrategy.TLS_CIPHER_SHUFFLE,
        BypassStrategy.TLS_ALPN_SKEW,
        BypassStrategy.TLS_EXTENSION_GREASE,
        BypassStrategy.TLS_HELLO_JUNK,
        BypassStrategy.TLS_LEGACY_HELLOS,
        BypassStrategy.TLS_SESSION_TICKET_SKEW,
        BypassStrategy.TLS_SESSION_ID_MANGLE,
        BypassStrategy.TLS_MULTI_SNI,
        BypassStrategy.TLS_COMPRESSION_FAKE,
        BypassStrategy.TLS_CHROME_HELLO_FAKE,
        BypassStrategy.TLS_FIREFOX_HELLO_FAKE,
        BypassStrategy.TLS_13_HELLO_FAKE,
        BypassStrategy.TLS_SESSION_ID_RAND,
        BypassStrategy.TLS_MIXED_CASE_SNI,
        BypassStrategy.TLS_SNI_SPLIT,
        BypassStrategy.TLS_CLIENT_HELLO_CHOP,
        BypassStrategy.TLS_APP_DATA_SPLIT,
        BypassStrategy.TLS_CLIENT_HELLO_SHUFFLE,
        BypassStrategy.TLS_RECORD_FRAGMENTATION,
        BypassStrategy.TLS_RECORD_PADDING,
        BypassStrategy.TLS_CLIENT_HELLO_GREASE_RANDOM,
        BypassStrategy.TLS_SNI_NULL_EXT,
        BypassStrategy.TLS_CLIENT_HELLO_PAD_EXTREME,
        BypassStrategy.TLS_EXTENSION_SHUFFLE,
        BypassStrategy.ECH_FRAG,
        BypassStrategy.TLS_SNI_SYMMETRIC_SPLIT,
        BypassStrategy.TLS_HANDSHAKE_RANDOM_PADDING,
        BypassStrategy.TLS_GREASE_SKEW,
        BypassStrategy.TLS_CLIENT_HELLO_PAD,
        BypassStrategy.TLS_0RTT_FAKE,
        BypassStrategy.TLS_CLIENT_HELLO_REORDER,
        BypassStrategy.TLS_ECH_FAKE,
        BypassStrategy.TLS_REC_CHOP,
        BypassStrategy.TLS_SNI_GREASE,
        BypassStrategy.TLS_SNI_REVERSE,
        BypassStrategy.TLS_SNI_OVERLAP_SKEW,
        BypassStrategy.TLS_CLIENT_HELLO_MULTI_PAD,
        BypassStrategy.TLS_SNI_JITTER_SPLIT,
        BypassStrategy.TLS_SNI_EXT_MANGLE,
        BypassStrategy.TLS_SNI_SKEW_ADVANCED,
        BypassStrategy.TLS_EXT_CHAOS,
        BypassStrategy.ECH_GREASE
    )

    override fun supportsStrategy(strategy: BypassStrategy): Boolean {
        return strategy in supportedStrategies
    }

    override suspend fun executeTcp(context: TcpExecutionContext) {
        if (context.strategy !in supportedStrategies) {
            throw UnsupportedStrategyException(context.strategy, executorType)
        }
        handleTlsStrategies(
            socket = context.socket,
            output = context.output,
            data = context.data,
            length = context.length,
            rnd = context.random,
            host = context.host,
            strategy = context.strategy,
            isFirstPacket = context.isFirstPacket
        )
    }

    suspend fun handleTlsStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy, isFirstPacket: Boolean = true) {
        if (strategy == BypassStrategy.DIRECT) {
            output.write(data, 0, length)
            output.flush()
            return
        }

        when (strategy) {
            BypassStrategy.SNI_SPLIT, BypassStrategy.TLS_SNI_SPLIT, BypassStrategy.TLS_SNI_SYMMETRIC_SPLIT -> {
                val sniPos = TlsParser.findSni(data, length)
                if (sniPos != -1) {
                    val hostname = TlsParser.extractHostname(data, length, sniPos)
                    val splitOffset = if (strategy == BypassStrategy.TLS_SNI_SYMMETRIC_SPLIT) {
                        if (hostname != null && hostname.length > 2) sniPos + (hostname.length / 2) else sniPos + 1
                    } else if (hostname != null && hostname.length >= 4) {
                        // Entropy/Mid-Domain split (split 2-3 bytes inside the SNI to evade DPI single-byte glue buffers)
                        sniPos + (hostname.length / 3).coerceIn(1, hostname.length - 1)
                    } else {
                        sniPos + 1
                    }
                    output.write(data, 0, splitOffset)
                    output.flush()
                    delay(rnd.nextLong(1, 4))
                    output.write(data, splitOffset, length - splitOffset)
                    output.flush()
                } else {
                    output.write(data, 0, length)
                    output.flush()
                }
            }
            BypassStrategy.SNI_TRIPLE -> {
                val sniPos = TlsParser.findSni(data, length)
                if (sniPos != -1 && length > sniPos + 3) {
                    output.write(data, 0, sniPos + 1)
                    output.flush()
                    delay(rnd.nextLong(1, 3))
                    output.write(data, sniPos + 1, 2)
                    output.flush()
                    delay(rnd.nextLong(1, 3))
                    output.write(data, sniPos + 3, length - (sniPos + 3))
                    output.flush()
                } else {
                    output.write(data, 0, length)
                    output.flush()
                }
            }
            BypassStrategy.SNI_MANGLE, BypassStrategy.TLS_MIXED_CASE_SNI -> {
                val fuzzed = TlsParser.mangleSni(data, length, rnd)
                output.write(fuzzed)
                output.flush()
            }
            BypassStrategy.TLS_DIRTY, BypassStrategy.TLS_REC_MANGLE, BypassStrategy.TLS_REC_CHOP -> {
                if (length > 5) {
                    output.write(data, 0, 5) // TLS Header
                    output.flush()
                    delay(rnd.nextLong(1, 5))
                    output.write(data, 5, length - 5)
                    output.flush()
                } else {
                    output.write(data, 0, length)
                    output.flush()
                }
            }
            BypassStrategy.TLS_PAD, BypassStrategy.TLS_PADDING_RAND, BypassStrategy.TLS_RECORD_PADDING, BypassStrategy.TLS_CLIENT_HELLO_PAD, BypassStrategy.TLS_HANDSHAKE_RANDOM_PADDING -> {
                val padded = TlsParser.addPadding(data, length, rnd.nextInt(16, 128))
                output.write(padded)
                output.flush()
            }
            BypassStrategy.TLS_CLIENT_HELLO_PAD_EXTREME, BypassStrategy.TLS_CLIENT_HELLO_MULTI_PAD -> {
                val padded = TlsParser.addPadding(data, length, rnd.nextInt(512, 1024))
                output.write(padded)
                output.flush()
            }
            BypassStrategy.TLS_GREASE, BypassStrategy.TLS_EXTENSION_GREASE, BypassStrategy.TLS_GREASE_SKEW, BypassStrategy.ECH_GREASE, BypassStrategy.TLS_CLIENT_HELLO_GREASE_RANDOM -> {
                val greased = TlsParser.addGrease(data, length, rnd)
                output.write(greased)
                output.flush()
            }
            BypassStrategy.FRAGMENT_MULTI, BypassStrategy.TLS_MULTI_FRAG, BypassStrategy.TLS_RECORD_FRAGMENTATION -> {
                var pos = 0
                val minSz = if (length > 200) 16 else 5
                val maxSz = if (length > 200) 64 else 50
                while (pos < length) {
                    val sz = rnd.nextInt(minSz, maxSz).coerceAtMost(length - pos)
                    output.write(data, pos, sz)
                    output.flush()
                    pos += sz
                    if (pos < length) delay(rnd.nextLong(1, 5))
                }
            }
            BypassStrategy.TLS_EXT_SKEW, BypassStrategy.TLS_EXTENSION_SHUFFLE, BypassStrategy.TLS_EXT_CHAOS, BypassStrategy.TLS_CLIENT_HELLO_REORDER, BypassStrategy.TLS_CLIENT_HELLO_SHUFFLE -> {
                val shuffled = TlsParser.shuffleExtensions(data, length, rnd)
                output.write(shuffled)
                output.flush()
            }
            BypassStrategy.TLS_REHANDSHAKE_FAKE -> {
                // Warning: Corrupting TLS payloads or faking cryptographic handshakes breaks application-level TLS context.
                // Reverting to transparent forward.
                output.write(data, 0, length)
                output.flush()
            }
            BypassStrategy.TLS_CIPHER_SHUFFLE -> {
                val shuffled = TlsParser.shuffleCiphers(data, length, rnd)
                output.write(shuffled)
                output.flush()
            }
            BypassStrategy.TLS_ALPN_SKEW -> {
                val modified = TlsParser.mangleAlpn(data, length, rnd)
                output.write(modified)
                output.flush()
            }
            BypassStrategy.TLS_HELLO_JUNK, BypassStrategy.TLS_LEGACY_HELLOS -> {
                // Warning: Corrupting TLS payloads or faking cryptographic handshakes breaks application-level TLS context.
                // Reverting to transparent forward.
                output.write(data, 0, length)
                output.flush()
            }
            BypassStrategy.TLS_SESSION_TICKET_SKEW, BypassStrategy.TLS_SESSION_ID_MANGLE, BypassStrategy.TLS_SESSION_ID_RAND, BypassStrategy.TLS_COMPRESSION_FAKE -> {
                val modified = TlsParser.mangleSessionId(data, length, rnd)
                output.write(modified)
                output.flush()
            }
            BypassStrategy.TLS_MULTI_SNI -> {
                // Warning: Corrupting TLS payloads or faking cryptographic handshakes breaks application-level TLS context.
                // Reverting to transparent forward.
                output.write(data, 0, length)
                output.flush()
            }
            BypassStrategy.TLS_CHROME_HELLO_FAKE, BypassStrategy.TLS_FIREFOX_HELLO_FAKE, BypassStrategy.TLS_13_HELLO_FAKE -> {
                // Warning: Corrupting TLS payloads or faking cryptographic handshakes breaks application-level TLS context.
                // Reverting to transparent forward.
                output.write(data, 0, length)
                output.flush()
            }
            BypassStrategy.TLS_APP_DATA_SPLIT -> {
                if (length > 5) {
                    output.write(data, 0, 5)
                    output.flush()
                    delay(rnd.nextLong(2, 10))
                    output.write(data, 5, length - 5)
                    output.flush()
                } else {
                    output.write(data, 0, length)
                    output.flush()
                }
            }
            BypassStrategy.TLS_CLIENT_HELLO_CHOP -> {
                if (!isFirstPacket) {
                    output.write(data, 0, length)
                    output.flush()
                    return
                }
                var pos = 0
                while (pos < length) {
                    val sz = if (length > 200) rnd.nextInt(4, 16) else 1
                    val chunk = sz.coerceAtMost(length - pos)
                    output.write(data, pos, chunk)
                    output.flush()
                    pos += chunk
                    if (pos < length) delay(rnd.nextLong(1, 3))
                }
            }
            BypassStrategy.ECH_FRAG -> {
                val echPos = TlsParser.findEch(data, length)
                if (echPos != -1 && echPos + 4 < length) {
                    val splitPos = echPos + 2 // Split inside ECH extension header/payload
                    output.write(data, 0, splitPos)
                    output.flush()
                    delay(rnd.nextLong(1, 4))
                    output.write(data, splitPos, length - splitPos)
                    output.flush()
                } else {
                    output.write(data, 0, length)
                    output.flush()
                }
            }
            BypassStrategy.TLS_SNI_GREASE, BypassStrategy.TLS_SNI_NULL_EXT -> {
                val modified = TlsParser.addSniGrease(data, length, rnd)
                output.write(modified)
                output.flush()
            }
            BypassStrategy.TLS_0RTT_FAKE -> {
                output.write(data, 0, length)
                output.flush()
                if (isFirstPacket) {
                    val fake0Rtt = FakePacketHelper.buildUdpNoise(rnd.nextInt(50, 150))
                    output.write(fake0Rtt)
                    output.flush()
                }
            }
            BypassStrategy.TLS_ECH_FAKE -> {
                val greased = TlsParser.addFakeEch(data, length, rnd)
                output.write(greased)
                output.flush()
            }
            BypassStrategy.TLS_SNI_REVERSE -> {
                val sni = TlsParser.extractSni(data, length)
                if (sni != null) {
                    val reversed = sni.reversed()
                    val modified = TlsParser.replaceSni(data, length, reversed)
                    output.write(modified)
                    output.flush()
                } else {
                    output.write(data, 0, length)
                    output.flush()
                }
            }
            BypassStrategy.TLS_SNI_OVERLAP_SKEW -> {
                val sniPos = TlsParser.findSni(data, length)
                if (sniPos != -1) {
                    TtlHelper.setTtl(socket, StrategyUtils.getFakeTtl(host, rnd))
                    output.write(data, 0, sniPos + 2)
                    output.flush()
                    delay(rnd.nextLong(1, 3))
                    TtlHelper.setTtl(socket, BypassConfig.currentTtl)
                    output.write(data, 0, length)
                    output.flush()
                } else {
                    output.write(data, 0, length)
                    output.flush()
                }
            }
            BypassStrategy.TLS_SNI_JITTER_SPLIT -> {
                val sniPos = TlsParser.findSni(data, length)
                if (sniPos != -1) {
                    val split = sniPos + rnd.nextInt(1, 3)
                    output.write(data, 0, split)
                    output.flush()
                    delay(rnd.nextLong(5, 20))
                    output.write(data, split, length - split)
                    output.flush()
                } else {
                    output.write(data, 0, length)
                    output.flush()
                }
            }
            BypassStrategy.TLS_SNI_EXT_MANGLE -> {
                val modified = TlsParser.mangleExtensions(data, length, rnd)
                output.write(modified)
                output.flush()
            }
            BypassStrategy.TLS_SNI_SKEW_ADVANCED, BypassStrategy.TLS_SNI_SKEW -> {
                val sniPos = TlsParser.findSni(data, length)
                if (sniPos != -1) {
                    TtlHelper.setTtl(socket, StrategyUtils.getFakeTtl(host, rnd))
                    output.write(data, 0, length)
                    output.flush()
                    delay(rnd.nextLong(2, 5))
                    TtlHelper.setTtl(socket, BypassConfig.currentTtl)
                    output.write(data, 0, length)
                    output.flush()
                } else {
                    output.write(data, 0, length)
                    output.flush()
                }
            }
            else -> {
                output.write(data, 0, length)
                output.flush()
            }
        }
    }
}
