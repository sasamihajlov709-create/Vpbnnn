package com.aistudio.pinkproxy.fresh

import android.util.Log
import java.io.OutputStream
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom
import kotlinx.coroutines.delay

object TcpBasicStrategyHandler : StrategyExecutor {
    override val executorType: StrategyExecutionRegistry.ExecutorType = StrategyExecutionRegistry.ExecutorType.TCP_BASIC_HANDLER
    override val supportedTransports: Set<TransportType> = setOf(TransportType.TCP)

    val supportedStrategies: Set<BypassStrategy> = setOf(
        BypassStrategy.FAKE_PACKET,
        BypassStrategy.TCP_OOB_DESYNC,
        BypassStrategy.OOB_DESYNC,
        BypassStrategy.GHOST_PACKETS,
        BypassStrategy.SOCKET_BUFFER_MANGLE,
        BypassStrategy.TCP_ZERO_WINDOW_STALL,
        BypassStrategy.TCP_MSS_CLAMP,
        BypassStrategy.TCP_FAST_RETRANSMIT_SIM,
        BypassStrategy.TCP_REORDER_SIM,
        BypassStrategy.TCP_FAST_OPEN_FAKE,
        BypassStrategy.TCP_RST_FAKE,
        BypassStrategy.TCP_TIMESTAMP_MANGLE,
        BypassStrategy.TCP_URGENT_RANDOM,
        BypassStrategy.TCP_REORDER_CHAOS,
        BypassStrategy.TCP_KEEP_ALIVE_FAKE,
        BypassStrategy.TCP_WINDOW_RESTRICT,
        BypassStrategy.TCP_WINDOW_SCAN,
        BypassStrategy.TCP_REORDER_DESYNC,
        BypassStrategy.TCP_URGENT_SKEW,
        BypassStrategy.SOCKET_BUFFER_SKEW,
        BypassStrategy.TCP_DATA_REPETITION,
        BypassStrategy.TCP_WINDOW_CLAMPING,
        BypassStrategy.TCP_GHOST_SKEW,
        BypassStrategy.PROTOCOL_CONFUSION_HTTP,
        BypassStrategy.TCP_RANDOM_PADDING,
        BypassStrategy.TCP_MSS_CLUMPING,
        BypassStrategy.TCP_HANDSHAKE_CHAOS,
        BypassStrategy.TCP_MSS_CLAMPER,
        BypassStrategy.TCP_TOS_MANGLE,
        BypassStrategy.PROTOCOL_CONFUSION_SSH,
        BypassStrategy.PROTOCOL_CONFUSION_BITTORRENT,
        BypassStrategy.PROTOCOL_CONFUSION_REDIS,
        BypassStrategy.PROTOCOL_CONFUSION_MEMCACHED,
        BypassStrategy.SSH_HANDSHAKE_FAKE,
        BypassStrategy.TCP_DATA_OOB_SKEW,
        BypassStrategy.TCP_SACK_FAKE,
        BypassStrategy.TCP_SEGMENT_DESYNC,
        BypassStrategy.TCP_ACK_SKEW,
        BypassStrategy.TCP_ZERO_WINDOW_DESYNC,
        BypassStrategy.SOCKET_BUFFER_CHAOS,
        BypassStrategy.TCP_OOB_SEGMENTATION,
        BypassStrategy.TCP_OVERLAP,
        BypassStrategy.TCP_WINDOW_SHAKE,
        BypassStrategy.TCP_OVERLAP_SKEW,
        BypassStrategy.TCP_WINDOW_RESIZE_PACING,
        BypassStrategy.TCP_KEEPALIVE_SKEW,
        BypassStrategy.TCP_URGENT_DESYNC,
        BypassStrategy.TCP_SYN_FLOOD_FAKE,
        BypassStrategy.TCP_DATA_DESYNC,
        BypassStrategy.TCP_ACK_SKEW_ADVANCED,
        BypassStrategy.TCP_FOOL_DPI,
        BypassStrategy.TCP_REVERSE_FRAG,
        BypassStrategy.TCP_DATA_DESYNC_OVERLAP,
        BypassStrategy.TCP_FRAGMENT_REORDER,
        BypassStrategy.TCP_RETRANS_FAKE,
        BypassStrategy.SOCKET_BUFFER_JITTER,
        BypassStrategy.TCP_TLS_SESSION_DESYNC,
        BypassStrategy.SOCKET_BUFFER_OSCILLATION,
        BypassStrategy.TCP_SACK_PANIC,
        BypassStrategy.TCP_SACK_SKEW,
        BypassStrategy.TCP_TRIPLE_DESYNC,
        BypassStrategy.TCP_FAKE_FIN,
        BypassStrategy.TCP_WINDOW_SHRINK,
        BypassStrategy.TCP_WINDOW_STALL,
        BypassStrategy.TCP_ZERO_WINDOW_OOB,
        BypassStrategy.TCP_TIMING_CHAOS,
        BypassStrategy.TCP_TLS_HELLO_FRAGMENT,
        BypassStrategy.TCP_TLS_SNI_CASE_MOD,
        BypassStrategy.TCP_REORDER,
        BypassStrategy.TCP_SEGMENT_OVERLAP,
        BypassStrategy.TCP_SEGMENT_REVERSE
    )

    override fun supportsStrategy(strategy: BypassStrategy): Boolean {
        return strategy in supportedStrategies
    }

    override suspend fun executeTcp(context: TcpExecutionContext) {
        if (context.strategy !in supportedStrategies) {
            throw UnsupportedStrategyException(context.strategy, executorType)
        }
        handleTcpStrategies(
            socket = context.socket,
            output = context.output,
            data = context.data,
            length = context.length,
            rnd = context.random,
            host = context.host,
            strategy = context.strategy
        )
    }

    suspend fun handleTcpStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy) {
        when (strategy) {
            BypassStrategy.PROTOCOL_CONFUSION_BITTORRENT, BypassStrategy.PROTOCOL_CONFUSION_MEMCACHED, 
            BypassStrategy.PROTOCOL_CONFUSION_REDIS, BypassStrategy.PROTOCOL_CONFUSION_SSH,
            BypassStrategy.PROTOCOL_CONFUSION_HTTP -> {
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
                // Warning: Attempting L4 packet manipulation or payload corruption over standard Java Sockets
                // actually breaks protocol semantics. Reverting to transparent forward.
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.TCP_WINDOW_SCAN -> {
                // Warning: Attempting L4 packet manipulation or payload corruption over standard Java Sockets
                // actually breaks protocol semantics. Reverting to transparent forward.
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.SOCKET_BUFFER_JITTER -> {
                // Warning: Attempting L4 packet manipulation or payload corruption over standard Java Sockets
                // actually breaks protocol semantics. Reverting to transparent forward.
                output.write(data, 0, length)
                output.flush()
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
                // Warning: Attempting L4 packet manipulation or payload corruption over standard Java Sockets
                // actually breaks protocol semantics. Reverting to transparent forward.
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.GHOST_PACKETS -> {
                // Warning: Attempting L4 packet manipulation or payload corruption over standard Java Sockets
                // actually breaks protocol semantics. Reverting to transparent forward.
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.TCP_ZERO_WINDOW_STALL -> {
                // Warning: Attempting L4 packet manipulation or payload corruption over standard Java Sockets
                // actually breaks protocol semantics. Reverting to transparent forward.
                output.write(data, 0, length)
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
                // Warning: Attempting L4 packet manipulation or payload corruption over standard Java Sockets
                // actually breaks protocol semantics. Reverting to transparent forward.
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.TCP_KEEP_ALIVE_FAKE, BypassStrategy.TCP_KEEPALIVE_SKEW -> {
                // Warning: Attempting L4 packet manipulation or payload corruption over standard Java Sockets
                // actually breaks protocol semantics. Reverting to transparent forward.
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.SOCKET_BUFFER_MANGLE, BypassStrategy.SOCKET_BUFFER_SKEW, BypassStrategy.SOCKET_BUFFER_CHAOS, BypassStrategy.SOCKET_BUFFER_OSCILLATION -> {
                // Warning: Attempting L4 packet manipulation or payload corruption over standard Java Sockets
                // actually breaks protocol semantics. Reverting to transparent forward.
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.TCP_FAST_RETRANSMIT_SIM, BypassStrategy.TCP_RETRANS_FAKE -> {
                // Warning: Attempting L4 packet manipulation or payload corruption over standard Java Sockets
                // actually breaks protocol semantics. Reverting to transparent forward.
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.TCP_FAST_OPEN_FAKE -> {
                // Warning: Attempting L4 packet manipulation or payload corruption over standard Java Sockets
                // actually breaks protocol semantics. Reverting to transparent forward.
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.TCP_RST_FAKE, BypassStrategy.TCP_FAKE_FIN -> {
                // Warning: Attempting L4 packet manipulation or payload corruption over standard Java Sockets
                // actually breaks protocol semantics. Reverting to transparent forward.
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
                // Warning: Attempting L4 packet manipulation or payload corruption over standard Java Sockets
                // actually breaks protocol semantics. Reverting to transparent forward.
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
                // Warning: Attempting L4 packet manipulation or payload corruption over standard Java Sockets
                // actually breaks protocol semantics. Reverting to transparent forward.
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
                // Warning: Attempting L4 packet manipulation or payload corruption over standard Java Sockets
                // actually breaks protocol semantics. Reverting to transparent forward.
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.TCP_OVERLAP, BypassStrategy.TCP_OVERLAP_SKEW, BypassStrategy.TCP_SEGMENT_OVERLAP -> {
                // Warning: Attempting L4 packet manipulation or payload corruption over standard Java Sockets
                // actually breaks protocol semantics. Reverting to transparent forward.
                output.write(data, 0, length)
                output.flush()
                return
            }
            BypassStrategy.TCP_WINDOW_SHAKE, BypassStrategy.TCP_WINDOW_RESIZE_PACING, BypassStrategy.TCP_WINDOW_SHRINK, BypassStrategy.TCP_WINDOW_STALL -> {
                // Warning: Attempting L4 packet manipulation or payload corruption over standard Java Sockets
                // actually breaks protocol semantics. Reverting to transparent forward.
                output.write(data, 0, length)
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
