package com.aistudio.pinkproxy.fresh

import android.util.Log
import java.io.OutputStream
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom
import kotlinx.coroutines.delay

object TcpBasicStrategyHandler {
    suspend fun handleTcpStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy) {
        when (strategy) {
            BypassStrategy.PROTOCOL_CONFUSION_BITTORRENT, BypassStrategy.PROTOCOL_CONFUSION_MEMCACHED, 
            BypassStrategy.PROTOCOL_CONFUSION_REDIS, BypassStrategy.PROTOCOL_CONFUSION_SSH -> {
                val protocol = strategy.name.substringAfter("PROTOCOL_CONFUSION_")
                val fake = FakePacketHelper.buildProtocolConfusion(protocol)
                TtlHelper.setTtl(socket, StrategyUtils.getFakeTtl(host, rnd))
                output.write(fake)
                output.flush()
                delay(rnd.nextLong(2, 6))
                TtlHelper.setTtl(socket, BypassConfig.currentTtl)
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.SSH_HANDSHAKE_FAKE -> {
                val sshBanner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n".toByteArray()
                TtlHelper.setTtl(socket, StrategyUtils.getFakeTtl(host, rnd))
                output.write(sshBanner)
                output.flush()
                delay(rnd.nextLong(3, 8))
                TtlHelper.setTtl(socket, BypassConfig.currentTtl)
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.TCP_WINDOW_SCAN -> {
                val winSizes = intArrayOf(512, 1024, 2048, 4096, 8192, 16384, 65535)
                var pos = 0
                var idx = 0
                while (pos < length) {
                    val sz = rnd.nextInt(1, 32).coerceAtMost(length - pos)
                    TtlHelper.setWindowSize(socket, winSizes[idx % winSizes.size])
                    output.write(data, pos, sz)
                    output.flush()
                    pos += sz
                    idx++
                    if (pos < length) delay(rnd.nextLong(1, 3))
                }
                TtlHelper.setWindowSize(socket, 65535)
                return
            }
            BypassStrategy.TCP_WINDOW_SIZE_JITTER -> {
                TtlHelper.setWindowSize(socket, rnd.nextInt(512, 4096))
                output.write(data, 0, length)
                output.flush()
                TtlHelper.setWindowSize(socket, 65535)
                return
            }
            BypassStrategy.TCP_BYTE_FRAG -> {
                 var pos = 0
                 while (pos < length) {
                      val sz = rnd.nextInt(1, 3).coerceAtMost(length - pos)
                      output.write(data, pos, sz)
                      output.flush()
                      pos += sz
                      if (pos < length) delay(rnd.nextLong(1, 4))
                 }
                 return
            }
            BypassStrategy.FAKE_PACKET, BypassStrategy.TCP_OOB_DESYNC, BypassStrategy.OOB_DESYNC -> {
                val decoy = if (rnd.nextBoolean()) FakePacketHelper.buildRealisticTlsHello("decoy.security.internal") else FakePacketHelper.buildFakeHttpRequest("decoy.security.internal")
                TtlHelper.setTtl(socket, StrategyUtils.getFakeTtl(host, rnd))
                output.write(decoy)
                output.flush()
                delay(rnd.nextLong(2, 6))
                TtlHelper.setTtl(socket, BypassConfig.currentTtl)
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.GHOST_PACKETS -> {
                val ghost = FakePacketHelper.buildUdpNoise(rnd.nextInt(32, 128))
                TtlHelper.setTtl(socket, StrategyUtils.getFakeTtl(host, rnd))
                output.write(ghost)
                output.flush()
                delay(rnd.nextLong(1, 4))
                TtlHelper.setTtl(socket, BypassConfig.currentTtl)
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.TCP_ZERO_WINDOW_STALL -> {
                TtlHelper.setWindowSize(socket, 1)
                output.write(data, 0, 1)
                output.flush()
                delay(rnd.nextLong(20, 80))
                TtlHelper.setWindowSize(socket, 65535)
                output.write(data, 1, length - 1)
                output.flush()
                return
            }
            BypassStrategy.TCP_MSS_CLAMP, BypassStrategy.TCP_MSS_CLAMPER -> {
                var pos = 0
                val recommendedMss = TrafficShaper.getRecommendedMss()
                val chunkSize = rnd.nextInt(recommendedMss / 2, recommendedMss).coerceAtLeast(64)
                while (pos < length) {
                    val sz = chunkSize.coerceAtMost(length - pos)
                    output.write(data, pos, sz)
                    output.flush()
                    pos += sz
                    if (pos < length) delay(rnd.nextLong(1, 3))
                }
                return
            }
            BypassStrategy.TCP_REORDER_SIM, BypassStrategy.TCP_REORDER_CHAOS -> {
                val part = length / 3
                if (part > 0) {
                    output.write(data, 0, part)
                    output.flush()
                    delay(rnd.nextLong(5, 15))
                    output.write(data, part, part)
                    output.flush()
                    delay(rnd.nextLong(5, 15))
                    output.write(data, part * 2, length - part * 2)
                    output.flush()
                } else {
                    output.write(data, 0, length)
                    output.flush()
                }
                return
            }
            BypassStrategy.TCP_WINDOW_RESTRICT, BypassStrategy.TCP_WINDOW_CLAMPING -> {
            try { socket.sendBufferSize = 256 } catch (e: Throwable) { Log.v("TcpBasicStrategy", "Failed to set small send buffer: ${e.message}") }
            var pos = 0
            while (pos < length) {
                val sz = rnd.nextInt(8, 32).coerceAtMost(length - pos)
                output.write(data, pos, sz)
                output.flush()
                pos += sz
                if (pos < length) delay(rnd.nextLong(1, 3))
            }
            try { socket.sendBufferSize = 64 * 1024 } catch (e: Throwable) { Log.v("TcpBasicStrategy", "Failed to restore send buffer: ${e.message}") }
                return
            }
            BypassStrategy.TCP_DATA_REPETITION -> {
                val repeatLen = minOf(10, length)
                TtlHelper.setTtl(socket, StrategyUtils.getFakeTtl(host, rnd))
                output.write(data, 0, repeatLen)
                output.flush()
                delay(rnd.nextLong(1, 3))
                TtlHelper.setTtl(socket, BypassConfig.currentTtl)
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.TCP_KEEP_ALIVE_FAKE -> {
                TtlHelper.setTtl(socket, StrategyUtils.getFakeTtl(host, rnd))
                output.write(ByteArray(0))
                output.flush()
                delay(rnd.nextLong(1, 3))
                TtlHelper.setTtl(socket, BypassConfig.currentTtl)
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.WINDOW_SIZE_MANGLE, BypassStrategy.TCP_WINDOW_SIZE_SKEW, BypassStrategy.TCP_WINDOW_SIZE_CHAOS, BypassStrategy.TCP_WINDOW_SIZE_OSCILLATION -> {
                TtlHelper.setWindowSize(socket, rnd.nextInt(10, 100))
                output.write(data, 0, length / 2)
                output.flush()
                delay(rnd.nextLong(5, 15))
                TtlHelper.setWindowSize(socket, 65535)
                output.write(data, length / 2, length - length / 2)
                output.flush()
                return
            }
            BypassStrategy.TCP_FAST_RETRANSMIT_SIM, BypassStrategy.TCP_RETRANS_FAKE -> {
                output.write(data, 0, length)
                output.flush()
                delay(rnd.nextLong(2, 6))
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.TCP_FAST_OPEN_FAKE -> {
                val fakeCookie = FakePacketHelper.buildUdpNoise(8)
                TtlHelper.setTtl(socket, StrategyUtils.getFakeTtl(host, rnd))
                output.write(fakeCookie)
                output.flush()
                delay(rnd.nextLong(1, 3))
                TtlHelper.setTtl(socket, BypassConfig.currentTtl)
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.TCP_RST_FAKE, BypassStrategy.TCP_FAKE_FIN -> {
                val rst = FakePacketHelper.buildUdpNoise(12)
                TtlHelper.setTtl(socket, StrategyUtils.getFakeTtl(host, rnd))
                output.write(rst)
                output.flush()
                delay(rnd.nextLong(1, 4))
                TtlHelper.setTtl(socket, BypassConfig.currentTtl)
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.TCP_TIMESTAMP_MANGLE, BypassStrategy.TCP_TOS_MANGLE -> {
                val part = length / 2
                output.write(data, 0, part)
                output.flush()
                delay(rnd.nextLong(2, 8))
                output.write(data, part, length - part)
                output.flush()
                return
            }
            BypassStrategy.TCP_URGENT_RANDOM, BypassStrategy.TCP_URGENT_SKEW, BypassStrategy.TCP_URGENT_DESYNC -> {
                output.write(data, 0, minOf(2, length))
                output.flush()
                delay(rnd.nextLong(1, 5))
                output.write(data, minOf(2, length), length - minOf(2, length))
                output.flush()
                return
            }
            BypassStrategy.TCP_REORDER_DESYNC, BypassStrategy.TCP_FRAGMENT_REORDER, BypassStrategy.TCP_REORDER -> {
                val part = length / 2
                if (part > 0) {
                    output.write(data, 0, part)
                    output.flush()
                    delay(rnd.nextLong(10, 30))
                    output.write(data, part, length - part)
                    output.flush()
                } else {
                    output.write(data, 0, length)
                    output.flush()
                }
                return
            }
            BypassStrategy.TCP_GHOST_SKEW, BypassStrategy.TCP_SYN_FLOOD_FAKE -> {
                val ghost = FakePacketHelper.buildUdpNoise(rnd.nextInt(10, 40))
                TtlHelper.setTtl(socket, StrategyUtils.getFakeTtl(host, rnd))
                output.write(ghost)
                output.flush()
                delay(rnd.nextLong(1, 4))
                TtlHelper.setTtl(socket, BypassConfig.currentTtl)
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.TCP_SMALL_CHUNKS, BypassStrategy.TCP_RANDOM_PADDING -> {
                var pos = 0
                while (pos < length) {
                    val sz = rnd.nextInt(4, 12).coerceAtMost(length - pos)
                    output.write(data, pos, sz)
                    output.flush()
                    pos += sz
                    if (pos < length) delay(rnd.nextLong(1, 3))
                }
                return
            }
            BypassStrategy.TCP_MSS_CLUMPING, BypassStrategy.TCP_HANDSHAKE_CHAOS -> {
                var pos = 0
                while (pos < length) {
                    val sz = rnd.nextInt(16, 48).coerceAtMost(length - pos)
                    output.write(data, pos, sz)
                    output.flush()
                    pos += sz
                    if (pos < length) delay(rnd.nextLong(1, 4))
                }
                return
            }
            BypassStrategy.TCP_DATA_OOB_SKEW, BypassStrategy.TCP_ZERO_WINDOW_OOB, BypassStrategy.TCP_OOB_SEGMENTATION -> {
                if (length > 1) {
                    output.write(data, 0, 1)
                    output.flush()
                    delay(rnd.nextLong(1, 3))
                    output.write(data, 1, length - 1)
                    output.flush()
                } else {
                    output.write(data, 0, length)
                    output.flush()
                }
                return
            }
            BypassStrategy.TCP_SACK_FAKE, BypassStrategy.TCP_SACK_PANIC, BypassStrategy.TCP_SACK_SKEW -> {
                var pos = 0
                while (pos < length) {
                    val sz = rnd.nextInt(10, 30).coerceAtMost(length - pos)
                    output.write(data, pos, sz)
                    output.flush()
                    pos += sz
                    if (pos < length) delay(rnd.nextLong(5, 15))
                }
                return
            }
            BypassStrategy.TCP_SEGMENT_DESYNC, BypassStrategy.TCP_DATA_DESYNC, BypassStrategy.TCP_DATA_DESYNC_OVERLAP, BypassStrategy.TCP_TRIPLE_DESYNC -> {
                val decoy = FakePacketHelper.buildRealisticTlsHello("decoy.internal")
                TtlHelper.setTtl(socket, StrategyUtils.getFakeTtl(host, rnd))
                output.write(decoy)
                output.flush()
                delay(rnd.nextLong(1, 3))
                TtlHelper.setTtl(socket, BypassConfig.currentTtl)
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.TCP_ACK_SKEW, BypassStrategy.TCP_ACK_SKEW_ADVANCED -> {
                val part = length / 3
                if (part > 0) {
                    output.write(data, 0, part)
                    output.flush()
                    delay(rnd.nextLong(10, 30))
                    output.write(data, part, length - part)
                    output.flush()
                } else {
                    output.write(data, 0, length)
                    output.flush()
                }
                return
            }
            BypassStrategy.TCP_ZERO_WINDOW_DESYNC -> {
                TtlHelper.setWindowSize(socket, 1)
                output.write(data, 0, minOf(1, length))
                output.flush()
                delay(rnd.nextLong(30, 90))
                TtlHelper.setWindowSize(socket, 65535)
                if (length > 1) {
                    output.write(data, 1, length - 1)
                    output.flush()
                }
                return
            }
            BypassStrategy.TCP_OVERLAP, BypassStrategy.TCP_OVERLAP_SKEW, BypassStrategy.TCP_SEGMENT_OVERLAP -> {
                val sniPos = if (length > 44 && data[0] == 0x16.toByte()) TlsParser.findSni(data, length) else 10
                val splitPos = if (sniPos > 0 && sniPos < length) sniPos else (length / 2).coerceAtLeast(1)
                
                // 1. Send fake overlapping segment with short TTL to poison DPI middlebox state
                val fakeOverlap = FakePacketHelper.getSmallNoise(splitPos)
                TtlHelper.setTtl(socket, StrategyUtils.getFakeTtl(host, rnd))
                output.write(fakeOverlap)
                output.flush()
                delay(rnd.nextLong(1, 4))
                
                // 2. Send real payload with valid TTL
                TtlHelper.setTtl(socket, BypassConfig.currentTtl)
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.TCP_WINDOW_SHAKE, BypassStrategy.TCP_WINDOW_RESIZE_PACING, BypassStrategy.TCP_WINDOW_SHRINK, BypassStrategy.TCP_WINDOW_STALL -> {
                TtlHelper.setWindowSize(socket, 256)
                output.write(data, 0, minOf(5, length))
                output.flush()
                delay(rnd.nextLong(5, 15))
                TtlHelper.setWindowSize(socket, 65535)
                output.write(data, minOf(5, length), length - minOf(5, length))
                output.flush()
                return
            }
            BypassStrategy.TCP_FOOL_DPI -> {
                val fake = FakePacketHelper.buildFakeHttpRequest("decoy.org")
                TtlHelper.setTtl(socket, StrategyUtils.getFakeTtl(host, rnd))
                output.write(fake)
                output.flush()
                delay(rnd.nextLong(1, 4))
                TtlHelper.setTtl(socket, BypassConfig.currentTtl)
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.TCP_REVERSE_FRAG, BypassStrategy.TCP_SEGMENT_REVERSE -> {
                val part = length / 2
                if (part > 0) {
                    output.write(data, 0, part)
                    output.flush()
                    delay(rnd.nextLong(5, 15))
                    output.write(data, part, length - part)
                    output.flush()
                } else {
                    output.write(data, 0, length)
                    output.flush()
                }
                return
            }
            BypassStrategy.TCP_TLS_SESSION_DESYNC -> {
                val fake = FakePacketHelper.buildRealisticTlsHello("decoy.internal")
                TtlHelper.setTtl(socket, StrategyUtils.getFakeTtl(host, rnd))
                output.write(fake)
                output.flush()
                delay(rnd.nextLong(2, 5))
                TtlHelper.setTtl(socket, BypassConfig.currentTtl)
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.TCP_TIMING_CHAOS -> {
                var pos = 0
                while (pos < length) {
                    val sz = rnd.nextInt(1, 5).coerceAtMost(length - pos)
                    output.write(data, pos, sz)
                    output.flush()
                    pos += sz
                    if (pos < length) delay(rnd.nextLong(5, 25))
                }
                return
            }
            BypassStrategy.TCP_TLS_HELLO_FRAGMENT, BypassStrategy.TCP_TLS_SNI_CASE_MOD -> {
                val part = length / 3
                if (part > 0) {
                    output.write(data, 0, part)
                    output.flush()
                    delay(rnd.nextLong(2, 8))
                    output.write(data, part, length - part)
                    output.flush()
                } else {
                    output.write(data, 0, length)
                    output.flush()
                }
                return
            }
            else -> {
                if (length > 15) {
                    val sz = rnd.nextInt(5, 10)
                    output.write(data, 0, sz)
                    output.flush()
                    delay(rnd.nextLong(1, 3))
                    output.write(data, sz, length - sz)
                    output.flush()
                } else {
                    output.write(data, 0, length)
                    output.flush()
                }
            }
        }
    }
}
