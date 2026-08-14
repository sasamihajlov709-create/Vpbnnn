package com.aistudio.pinkproxy.fresh

import java.io.OutputStream
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom
import kotlinx.coroutines.delay

object TlsStrategyHandler : StrategyExecutor {
    override val executorType: StrategyExecutionRegistry.ExecutorType = StrategyExecutionRegistry.ExecutorType.TLS_HANDLER
    override val supportedTransports: Set<TransportType> = setOf(TransportType.TCP)

    override fun supportsStrategy(strategy: BypassStrategy): Boolean {
        return StrategyExecutionRegistry.getExecutorType(strategy) == executorType
    }

    override suspend fun executeTcp(context: TcpExecutionContext) {
        handleTlsStrategies(
            socket = context.socket,
            output = context.output,
            data = context.data,
            length = context.length,
            rnd = context.random,
            host = context.host,
            strategy = context.strategy
        )
    }

    suspend fun handleTlsStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy) {
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
                while (pos < length) {
                    val sz = rnd.nextInt(5, 50).coerceAtMost(length - pos)
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
                output.write(data, 0, length)
                output.flush()
                delay(rnd.nextLong(10, 30))
                val hello = FakePacketHelper.buildRealisticTlsHello(host)
                output.write(hello)
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
                val junk = FakePacketHelper.buildUdpNoise(rnd.nextInt(10, 30))
                TtlHelper.setTtl(socket, StrategyUtils.getFakeTtl(host, rnd))
                output.write(junk)
                output.flush()
                delay(rnd.nextLong(1, 4))
                TtlHelper.setTtl(socket, BypassConfig.currentTtl)
                output.write(data, 0, length)
                output.flush()
            }
            BypassStrategy.TLS_SESSION_TICKET_SKEW, BypassStrategy.TLS_SESSION_ID_MANGLE, BypassStrategy.TLS_SESSION_ID_RAND, BypassStrategy.TLS_COMPRESSION_FAKE -> {
                val modified = TlsParser.mangleSessionId(data, length, rnd)
                output.write(modified)
                output.flush()
            }
            BypassStrategy.TLS_MULTI_SNI -> {
                 val multiSni = TlsParser.addExtraSni(data, length, "decoy.org", rnd)
                 output.write(multiSni)
                 output.flush()
            }
            BypassStrategy.TLS_CHROME_HELLO_FAKE, BypassStrategy.TLS_FIREFOX_HELLO_FAKE, BypassStrategy.TLS_13_HELLO_FAKE -> {
                val fakeHello = when(strategy) {
                    BypassStrategy.TLS_CHROME_HELLO_FAKE -> FakePacketHelper.buildChromeHello(host)
                    BypassStrategy.TLS_FIREFOX_HELLO_FAKE -> FakePacketHelper.buildFirefoxHello(host)
                    else -> FakePacketHelper.buildTls13Hello(host)
                }
                TtlHelper.setTtl(socket, StrategyUtils.getFakeTtl(host, rnd))
                output.write(fakeHello)
                output.flush()
                delay(rnd.nextLong(2, 6))
                TtlHelper.setTtl(socket, BypassConfig.currentTtl)
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
                var pos = 0
                while (pos < length) {
                    output.write(data, pos, 1)
                    output.flush()
                    pos++
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
                val fake0Rtt = FakePacketHelper.buildUdpNoise(rnd.nextInt(50, 150))
                output.write(fake0Rtt)
                output.flush()
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
