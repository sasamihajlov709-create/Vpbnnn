package com.aistudio.pinkproxy.fresh

import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom
import kotlinx.coroutines.delay

object StrategyHandlers {

    private fun getFakeTtl(host: String, rnd: ThreadLocalRandom, overrideTtl: Int = -1): Int {
        if (overrideTtl > 0) return overrideTtl
        val disc = AutoTtlProber.getDiscoveredTtl(host)
        if (disc != null && disc > 1) return disc
        return rnd.nextInt(2, 5)
    }

    suspend fun handleHttpStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy) {
        if (strategy == BypassStrategy.DIRECT) {
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.HTTP_HEADER_CASE_CHAOS) {
            val fuzzed = FakePacketHelper.randomizeHeaderCase(data, length)
            output.write(fuzzed, 0, fuzzed.size)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.HTTP_METHOD_CASE_MANGLE) {
            val fuzzed = FakePacketHelper.mangleHttpMethodCase(data, length)
            output.write(fuzzed, 0, fuzzed.size)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.HTTP_CHUNKED_FAKE) {
            var pos = 0
            while (pos < length) {
                val sz = rnd.nextInt(1, 10).coerceAtMost(length - pos)
                output.write(data, pos, sz)
                output.flush()
                pos += sz
                if (pos < length) delay(rnd.nextLong(1, 15))
            }
            return
        }

        if (strategy == BypassStrategy.HTTP_PIPELINE_FAKE) {
             output.write(data, 0, length)
             output.flush()
             val fake = "GET /favicon.ico HTTP/1.1\r\nHost: $host\r\nConnection: keep-alive\r\n\r\n".toByteArray()
             output.write(fake)
             output.flush()
             return
        }

        if (strategy == BypassStrategy.HTTP_METHOD_FAKE) {
            val fakeReq = FakePacketHelper.buildFakeHttpRequest(host)
            TtlHelper.setTtl(socket, getFakeTtl(host, rnd))
            output.write(fakeReq)
            output.flush()
            delay(rnd.nextLong(2, 6))
            TtlHelper.setTtl(socket, 64)
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.HTTP2_PREAMBLE_FAKE) {
            val preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray()
            val fakeSettings = byteArrayOf(0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00)
            TtlHelper.setTtl(socket, getFakeTtl(host, rnd))
            output.write(preface)
            output.write(fakeSettings)
            output.flush()
            delay(rnd.nextLong(1, 4))
            TtlHelper.setTtl(socket, 64)
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.TCP_REARRANGE_CHUNKS) {
            if (length > 100) {
                val c1Size = length / 3
                val c2Size = length / 3
                val c3Size = length - c1Size - c2Size
                
                val fakeTtl = getFakeTtl(host, rnd)
                
                // 1. Ghost C1
                TtlHelper.setTtl(socket, fakeTtl)
                output.write(data, 0, c1Size)
                output.flush()
                delay(rnd.nextLong(2, 5))
                
                // 2. Ghost C1+C2
                output.write(data, 0, c1Size + c2Size)
                output.flush()
                delay(rnd.nextLong(2, 5))
                
                // 3. Real C1
                TtlHelper.setTtl(socket, 64)
                output.write(data, 0, c1Size)
                output.flush()
                delay(rnd.nextLong(1, 3))
                
                // 4. Real C2
                output.write(data, c1Size, c2Size)
                output.flush()
                delay(rnd.nextLong(1, 3))
                
                // 5. Real C3
                output.write(data, c1Size + c2Size, c3Size)
                output.flush()
            } else {
                output.write(data, 0, length)
                output.flush()
            }
            return
        }

        if (strategy == BypassStrategy.HTTP_FRAGMENT) {
            var pos = 0
            while (pos < length) {
                output.write(data, pos, 1)
                output.flush()
                pos += 1
                if (pos < length) delay(rnd.nextLong(1, 5))
            }
            return
        }

        if (strategy == BypassStrategy.WS_HANDSHAKE_FAKE) {
            val handshake = "GET /chat HTTP/1.1\r\nHost: $host\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n".toByteArray()
            output.write(handshake)
            output.flush()
            delay(rnd.nextLong(1, 4))
            output.write(data, 0, length)
            output.flush()
            return
        }

        val str = if (strategy == BypassStrategy.HTTP_HOST_SMUGGLE || 
                      strategy == BypassStrategy.HTTP_HOST_REORDER || 
                      strategy == BypassStrategy.HTTP_KEEP_ALIVE_FAKE ||
                      strategy == BypassStrategy.HTTP_HOST_SPACE ||
                      strategy == BypassStrategy.HTTP_VERSION_SKEW ||
                      strategy == BypassStrategy.HTTP_HOST_TAB_MANGLE ||
                      strategy == BypassStrategy.HTTP_MULTI_LINE_MANGLE ||
                      strategy == BypassStrategy.HTTP_HOST_FOLDING ||
                      strategy == BypassStrategy.HTTP_HOST_MANGLE ||
                      strategy == BypassStrategy.HTTP_HOST_CASE_MANGLE ||
                      strategy == BypassStrategy.HTTP_AUTH_RANDOM ||
                      strategy == BypassStrategy.HTTP_CONNECTION_CLOSE_SKEW ||
                      strategy == BypassStrategy.HTTP_HEADER_FUZZING ||
                      strategy == BypassStrategy.HTTP_HEADER_MANGLE ||
                      strategy == BypassStrategy.HTTP_HOST_DOT_MANGLE ||
                      strategy == BypassStrategy.HTTP_HOST_REVERSE ||
                      strategy == BypassStrategy.HTTP_LINE_SPLIT ||
                      strategy == BypassStrategy.HTTP_METHOD_SPACE_MANGLE ||
                      strategy == BypassStrategy.HTTP_RANGE_SKEW ||
                      strategy == BypassStrategy.HTTP_USER_AGENT_SKEW) {
            String(data, 0, length, Charsets.US_ASCII)
        } else null

        if (strategy == BypassStrategy.HTTP_AUTH_RANDOM && str != null) {
            val modified = str.replace("Host: $host", "Host: $host\r\nAuthorization: Basic " + android.util.Base64.encodeToString(FakePacketHelper.buildUdpNoise(12), android.util.Base64.NO_WRAP))
            val outData = modified.toByteArray()
            output.write(outData, 0, outData.size)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.HTTP_CONNECTION_CLOSE_SKEW && str != null) {
            val modified = str.replace("Host: $host", "Host: $host\r\nCoNnEcTiOn: ClOsE")
            val outData = modified.toByteArray()
            output.write(outData, 0, outData.size)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.HTTP_HEADER_FUZZING && str != null) {
            val modified = str.replace("Host: $host", "Host: $host\r\nX-Fuzzed-Header-" + rnd.nextInt(100) + ": " + rnd.nextInt(1000000))
            val outData = modified.toByteArray()
            output.write(outData, 0, outData.size)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.HTTP_HEADER_MANGLE && str != null) {
            val modified = str.replace("Accept:", "AcCePt: ")
            val outData = modified.toByteArray()
            output.write(outData, 0, outData.size)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.HTTP_HOST_DOT_MANGLE && str != null) {
            val modified = str.replace("Host: $host", "Host: $host.")
            val outData = modified.toByteArray()
            output.write(outData, 0, outData.size)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.HTTP_HOST_REVERSE && str != null) {
            val modified = str.replace("Host: $host", "Host: " + host.reversed())
            val outData = modified.toByteArray()
            output.write(outData, 0, outData.size)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.HTTP_LINE_SPLIT && str != null) {
            val modified = str.replace("\r\n", "\r\n ")
            val outData = modified.toByteArray()
            output.write(outData, 0, outData.size)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.HTTP_METHOD_SPACE_MANGLE && str != null) {
            val modified = str.replace("GET ", "GET\t").replace("POST ", "POST\t")
            val outData = modified.toByteArray()
            output.write(outData, 0, outData.size)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.HTTP_RANGE_SKEW && str != null) {
            val modified = str.replace("Host: $host", "Host: $host\r\nRange: bytes=0-0")
            val outData = modified.toByteArray()
            output.write(outData, 0, outData.size)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.HTTP_USER_AGENT_SKEW && str != null) {
            val modified = str.replace("User-Agent:", "UsEr-AgEnT:")
            val outData = modified.toByteArray()
            output.write(outData, 0, outData.size)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.HTTP_HOST_SMUGGLE && str != null) {
            if (str.contains("Host:")) {
                val smuggled = str.replaceFirst("Host: $host", "Host: mydecoy.com\r\nHost: $host")
                val outData = smuggled.toByteArray()
                output.write(outData, 0, outData.size)
                output.flush()
                return
            }
        }

        if (strategy == BypassStrategy.HTTP_HOST_REORDER && str != null) {
            val hostHeader = "Host: $host\r\n"
            if (str.contains(hostHeader)) {
                val smuggled = str.replaceFirst(hostHeader, "")
                val endOfHeaders = smuggled.indexOf("\r\n\r\n")
                if (endOfHeaders != -1) {
                    val reordered = smuggled.substring(0, endOfHeaders + 2) + hostHeader + smuggled.substring(endOfHeaders + 2)
                    val outData = reordered.toByteArray()
                    output.write(outData, 0, outData.size)
                    output.flush()
                    return
                }
            }
        }

        if (strategy == BypassStrategy.HTTP_KEEP_ALIVE_FAKE && str != null) {
             val modified = str.replace("Connection: keep-alive", "Connection: keep-alive, Upgrade")
             val outData = modified.toByteArray()
             output.write(outData, 0, outData.size)
             output.flush()
             return
        }

        if (strategy == BypassStrategy.HTTP_HOST_SPACE && str != null) {
            val modified = str.replace("Host: $host", "Host:  $host")
            val outData = modified.toByteArray()
            output.write(outData, 0, outData.size)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.HTTP_VERSION_SKEW && str != null) {
            val modified = str.replace("HTTP/1.1", "HTTP/1.2")
            val outData = modified.toByteArray()
            output.write(outData, 0, outData.size)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.HTTP_HOST_TAB_MANGLE && str != null) {
            val modified = str.replace("Host: $host", "Host:\t$host")
            val outData = modified.toByteArray()
            output.write(outData, 0, outData.size)
            output.flush()
            return
        }

        if ((strategy == BypassStrategy.HTTP_MULTI_LINE_MANGLE || strategy == BypassStrategy.HTTP_HOST_FOLDING) && str != null) {
            val modified = str.replace("Host: $host", "Host:\r\n  $host")
            val outData = modified.toByteArray()
            output.write(outData, 0, outData.size)
            output.flush()
            return
        }

        if ((strategy == BypassStrategy.HTTP_HOST_MANGLE || strategy == BypassStrategy.HTTP_HOST_CASE_MANGLE) && str != null) {
            val mixedHostHeader = if (rnd.nextBoolean()) "hOsT: $host" else "Host: " + host.uppercase()
            val modified = str.replace("Host: $host", mixedHostHeader)
            val outData = modified.toByteArray()
            output.write(outData, 0, outData.size)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.PROTOCOL_CONFUSION_HTTP) {
            val fakeTls = FakePacketHelper.buildRealisticTlsHello(host)
            output.write(fakeTls)
            output.flush()
            delay(rnd.nextLong(2, 5))
        }

        val part = length / 2
        if (length > 10) {
            output.write(data, 0, part)
            output.flush()
            delay(rnd.nextLong(2, 5))
            output.write(data, part, length - part)
            output.flush()
        } else {
            output.write(data, 0, length)
            output.flush()
        }
    }

    suspend fun handleTcpStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy) {
        if (strategy == BypassStrategy.PROTOCOL_CONFUSION_BITTORRENT) {
            val fake = FakePacketHelper.buildProtocolConfusion("BITTORRENT")
            TtlHelper.setTtl(socket, getFakeTtl(host, rnd))
            output.write(fake)
            output.flush()
            delay(rnd.nextLong(2, 6))
            TtlHelper.setTtl(socket, 64)
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.PROTOCOL_CONFUSION_MEMCACHED) {
            val fake = FakePacketHelper.buildProtocolConfusion("MEMCACHED")
            TtlHelper.setTtl(socket, getFakeTtl(host, rnd))
            output.write(fake)
            output.flush()
            delay(rnd.nextLong(2, 6))
            TtlHelper.setTtl(socket, 64)
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.PROTOCOL_CONFUSION_REDIS) {
            val fake = FakePacketHelper.buildProtocolConfusion("REDIS")
            TtlHelper.setTtl(socket, getFakeTtl(host, rnd))
            output.write(fake)
            output.flush()
            delay(rnd.nextLong(2, 6))
            TtlHelper.setTtl(socket, 64)
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.PROTOCOL_CONFUSION_SSH) {
            val fake = FakePacketHelper.buildProtocolConfusion("SSH")
            TtlHelper.setTtl(socket, getFakeTtl(host, rnd))
            output.write(fake)
            output.flush()
            delay(rnd.nextLong(2, 6))
            TtlHelper.setTtl(socket, 64)
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.SSH_HANDSHAKE_FAKE) {
            val sshBanner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n".toByteArray()
            TtlHelper.setTtl(socket, getFakeTtl(host, rnd))
            output.write(sshBanner)
            output.flush()
            delay(rnd.nextLong(3, 8))
            TtlHelper.setTtl(socket, 64)
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.TCP_WINDOW_SCAN) {
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

        if (strategy == BypassStrategy.TCP_WINDOW_SIZE_JITTER) {
            TtlHelper.setWindowSize(socket, rnd.nextInt(512, 4096))
            output.write(data, 0, length)
            output.flush()
            TtlHelper.setWindowSize(socket, 65535)
            return
        }
        
        if (strategy == BypassStrategy.TCP_BYTE_FRAG) {
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

        if (strategy == BypassStrategy.FAKE_PACKET || strategy == BypassStrategy.TCP_OOB_DESYNC || strategy == BypassStrategy.OOB_DESYNC) {
            val decoy = if (rnd.nextBoolean()) FakePacketHelper.buildRealisticTlsHello("decoy.security.internal") else FakePacketHelper.buildFakeHttpRequest("decoy.security.internal")
            TtlHelper.setTtl(socket, getFakeTtl(host, rnd))
            output.write(decoy)
            output.flush()
            delay(rnd.nextLong(2, 6))
            TtlHelper.setTtl(socket, 64)
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.GHOST_PACKETS) {
            val ghost = FakePacketHelper.buildUdpNoise(rnd.nextInt(32, 128))
            TtlHelper.setTtl(socket, getFakeTtl(host, rnd))
            output.write(ghost)
            output.flush()
            delay(rnd.nextLong(1, 4))
            TtlHelper.setTtl(socket, 64)
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.TCP_ZERO_WINDOW_STALL) {
            TtlHelper.setWindowSize(socket, 1)
            output.write(data, 0, 1)
            output.flush()
            delay(rnd.nextLong(20, 80))
            TtlHelper.setWindowSize(socket, 65535)
            output.write(data, 1, length - 1)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.TCP_MSS_CLAMP || strategy == BypassStrategy.TCP_MSS_CLAMPER) {
            var pos = 0
            val chunkSize = rnd.nextInt(64, 128)
            while (pos < length) {
                val sz = chunkSize.coerceAtMost(length - pos)
                output.write(data, pos, sz)
                output.flush()
                pos += sz
                if (pos < length) delay(rnd.nextLong(1, 3))
            }
            return
        }

        if (strategy == BypassStrategy.TCP_REORDER_SIM || strategy == BypassStrategy.TCP_REORDER_CHAOS) {
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

        if (strategy == BypassStrategy.TCP_WINDOW_RESTRICT || strategy == BypassStrategy.TCP_WINDOW_CLAMPING) {
            try { socket.sendBufferSize = 256 } catch (e: Throwable) {}
            var pos = 0
            while (pos < length) {
                val sz = rnd.nextInt(8, 32).coerceAtMost(length - pos)
                output.write(data, pos, sz)
                output.flush()
                pos += sz
                if (pos < length) delay(rnd.nextLong(1, 3))
            }
            try { socket.sendBufferSize = 64 * 1024 } catch (e: Throwable) {}
            return
        }

        if (strategy == BypassStrategy.TCP_DATA_REPETITION) {
            val repeatLen = minOf(10, length)
            TtlHelper.setTtl(socket, getFakeTtl(host, rnd))
            output.write(data, 0, repeatLen)
            output.flush()
            delay(rnd.nextLong(1, 3))
            TtlHelper.setTtl(socket, 64)
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.TCP_KEEP_ALIVE_FAKE) {
            // Write 0-byte keepalive probes before data
            TtlHelper.setTtl(socket, getFakeTtl(host, rnd))
            output.write(ByteArray(0))
            output.flush()
            delay(rnd.nextLong(1, 3))
            TtlHelper.setTtl(socket, 64)
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.WINDOW_SIZE_MANGLE || strategy == BypassStrategy.TCP_WINDOW_SIZE_SKEW || strategy == BypassStrategy.TCP_WINDOW_SIZE_CHAOS || strategy == BypassStrategy.TCP_WINDOW_SIZE_OSCILLATION) {
            TtlHelper.setWindowSize(socket, rnd.nextInt(10, 100))
            output.write(data, 0, length / 2)
            output.flush()
            delay(rnd.nextLong(5, 15))
            TtlHelper.setWindowSize(socket, 65535)
            output.write(data, length / 2, length - length / 2)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.TCP_FAST_RETRANSMIT_SIM || strategy == BypassStrategy.TCP_RETRANS_FAKE) {
            output.write(data, 0, length)
            output.flush()
            delay(rnd.nextLong(2, 6))
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.TCP_FAST_OPEN_FAKE) {
            val fakeCookie = FakePacketHelper.buildUdpNoise(8)
            TtlHelper.setTtl(socket, getFakeTtl(host, rnd))
            output.write(fakeCookie)
            output.flush()
            delay(rnd.nextLong(1, 3))
            TtlHelper.setTtl(socket, 64)
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.TCP_RST_FAKE || strategy == BypassStrategy.TCP_FAKE_FIN) {
            val rst = FakePacketHelper.buildUdpNoise(12)
            TtlHelper.setTtl(socket, getFakeTtl(host, rnd))
            output.write(rst)
            output.flush()
            delay(rnd.nextLong(1, 4))
            TtlHelper.setTtl(socket, 64)
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.TCP_TIMESTAMP_MANGLE || strategy == BypassStrategy.TCP_TOS_MANGLE) {
            val part = length / 2
            output.write(data, 0, part)
            output.flush()
            delay(rnd.nextLong(2, 8))
            output.write(data, part, length - part)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.TCP_URGENT_RANDOM || strategy == BypassStrategy.TCP_URGENT_SKEW || strategy == BypassStrategy.TCP_URGENT_DESYNC) {
            output.write(data, 0, minOf(2, length))
            output.flush()
            delay(rnd.nextLong(1, 5))
            output.write(data, minOf(2, length), length - minOf(2, length))
            output.flush()
            return
        }

        if (strategy == BypassStrategy.TCP_REORDER_DESYNC || strategy == BypassStrategy.TCP_FRAGMENT_REORDER || strategy == BypassStrategy.TCP_REORDER) {
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

        if (strategy == BypassStrategy.TCP_GHOST_SKEW || strategy == BypassStrategy.TCP_SYN_FLOOD_FAKE) {
            val ghost = FakePacketHelper.buildUdpNoise(rnd.nextInt(10, 40))
            TtlHelper.setTtl(socket, getFakeTtl(host, rnd))
            output.write(ghost)
            output.flush()
            delay(rnd.nextLong(1, 4))
            TtlHelper.setTtl(socket, 64)
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.TCP_SMALL_CHUNKS || strategy == BypassStrategy.TCP_RANDOM_PADDING) {
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

        if (strategy == BypassStrategy.TCP_MSS_CLUMPING || strategy == BypassStrategy.TCP_HANDSHAKE_CHAOS) {
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

        if (strategy == BypassStrategy.TCP_DATA_OOB_SKEW || strategy == BypassStrategy.TCP_ZERO_WINDOW_OOB || strategy == BypassStrategy.TCP_OOB_SEGMENTATION) {
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

        if (strategy == BypassStrategy.TCP_SACK_FAKE || strategy == BypassStrategy.TCP_SACK_PANIC || strategy == BypassStrategy.TCP_SACK_SKEW) {
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

        if (strategy == BypassStrategy.TCP_SEGMENT_DESYNC || strategy == BypassStrategy.TCP_DATA_DESYNC || strategy == BypassStrategy.TCP_DATA_DESYNC_OVERLAP || strategy == BypassStrategy.TCP_TRIPLE_DESYNC) {
            val decoy = FakePacketHelper.buildRealisticTlsHello("decoy.internal")
            TtlHelper.setTtl(socket, getFakeTtl(host, rnd))
            output.write(decoy)
            output.flush()
            delay(rnd.nextLong(1, 3))
            TtlHelper.setTtl(socket, 64)
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.TCP_ACK_SKEW || strategy == BypassStrategy.TCP_ACK_SKEW_ADVANCED) {
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

        if (strategy == BypassStrategy.TCP_ZERO_WINDOW_DESYNC) {
            TtlHelper.setWindowSize(socket, 0)
            delay(rnd.nextLong(10, 40))
            TtlHelper.setWindowSize(socket, 65535)
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.TCP_OVERLAP || strategy == BypassStrategy.TCP_OVERLAP_SKEW || strategy == BypassStrategy.TCP_SEGMENT_OVERLAP) {
            if (length > 2) {
                output.write(data, 0, 2)
                output.flush()
                delay(rnd.nextLong(1, 3))
                output.write(data, 2, length - 2)
                output.flush()
            } else {
                output.write(data, 0, length)
                output.flush()
            }
            return
        }

        if (strategy == BypassStrategy.TCP_WINDOW_SHAKE || strategy == BypassStrategy.TCP_WINDOW_RESIZE_PACING || strategy == BypassStrategy.TCP_WINDOW_SHRINK || strategy == BypassStrategy.TCP_WINDOW_STALL) {
            TtlHelper.setWindowSize(socket, 256)
            output.write(data, 0, minOf(5, length))
            output.flush()
            delay(rnd.nextLong(5, 15))
            TtlHelper.setWindowSize(socket, 65535)
            output.write(data, minOf(5, length), length - minOf(5, length))
            output.flush()
            return
        }

        if (strategy == BypassStrategy.TCP_KEEPALIVE_SKEW) {
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.TCP_FOOL_DPI) {
            val fake = FakePacketHelper.buildFakeHttpRequest("decoy.org")
            TtlHelper.setTtl(socket, getFakeTtl(host, rnd))
            output.write(fake)
            output.flush()
            delay(rnd.nextLong(1, 4))
            TtlHelper.setTtl(socket, 64)
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.TCP_REVERSE_FRAG || strategy == BypassStrategy.TCP_SEGMENT_REVERSE) {
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

        if (strategy == BypassStrategy.TCP_TLS_SESSION_DESYNC) {
            val fake = FakePacketHelper.buildRealisticTlsHello("decoy.internal")
            TtlHelper.setTtl(socket, getFakeTtl(host, rnd))
            output.write(fake)
            output.flush()
            delay(rnd.nextLong(2, 5))
            TtlHelper.setTtl(socket, 64)
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.TCP_TIMING_CHAOS) {
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

        if (strategy == BypassStrategy.TCP_TLS_HELLO_FRAGMENT || strategy == BypassStrategy.TCP_TLS_SNI_CASE_MOD) {
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

    suspend fun handleTlsStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy) {
        var finalData = data
        var finalLen = length
        
        if (strategy == BypassStrategy.TLS_COMPRESSION_FAKE) {
            val fakeHello = FakePacketHelper.buildRealisticTlsHello(host)
            if (fakeHello.size > 3) {
                fakeHello[fakeHello.size - 3] = 0x01
            }
            TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
            output.write(fakeHello)
            output.flush()
            delay(rnd.nextLong(2, 6))
            TtlHelper.setTtl(socket, 64)
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.TLS_PADDING_RAND) {
            finalData = FakePacketHelper.injectTlsPadding(finalData, finalLen, rnd.nextInt(16, 128))
            finalLen = finalData.size
        }

        if (strategy == BypassStrategy.TLS_SNI_NULL_EXT) {
            val nullExt = FakePacketHelper.buildUdpNoise(16)
            finalData = FakePacketHelper.injectExtension(finalData, finalLen, 0x00ff, nullExt)
            finalLen = finalData.size
        }

        if (strategy == BypassStrategy.TLS_REC_MANGLE) {
            if (finalLen >= 3 && finalData[0] == 0x16.toByte()) {
                val mangled = finalData.copyOf(finalLen)
                mangled[1] = 0x03.toByte()
                mangled[2] = 0x01.toByte()
                finalData = mangled
            }
        }

        if (strategy == BypassStrategy.TLS_APP_DATA_SPLIT) {
            var pos = 0
            while (pos < finalLen) {
                val sz = rnd.nextInt(16, 128).coerceAtMost(finalLen - pos)
                output.write(finalData, pos, sz)
                output.flush()
                pos += sz
                if (pos < finalLen) delay(rnd.nextLong(1, 4))
            }
            return
        }

        if (strategy == BypassStrategy.TLS_CLIENT_HELLO_CHOP || strategy == BypassStrategy.TLS_REC_CHOP) {
            val chop1 = finalLen / 3
            val chop2 = (finalLen * 2) / 3
            if (chop1 > 0 && chop2 > chop1 && finalLen > chop2) {
                output.write(finalData, 0, chop1)
                output.flush()
                delay(rnd.nextLong(2, 6))
                output.write(finalData, chop1, chop2 - chop1)
                output.flush()
                delay(rnd.nextLong(2, 6))
                output.write(finalData, chop2, finalLen - chop2)
                output.flush()
            } else {
                output.write(finalData, 0, finalLen)
                output.flush()
            }
            return
        }
        
        if (strategy == BypassStrategy.ECH_GREASE || strategy == BypassStrategy.ECH_FRAG) {
            finalData = TlsParser.injectEchGrease(data, length)
            finalLen = finalData.size
        }

        if (strategy == BypassStrategy.TLS_PAD || strategy == BypassStrategy.TLS_RECORD_PADDING) {
            finalData = FakePacketHelper.injectTlsPadding(finalData, finalLen, rnd.nextInt(64, 256))
            finalLen = finalData.size
        }

        if (strategy == BypassStrategy.SNI_MANGLE) {
            val mangledHost = host.reversed()
            finalData = FakePacketHelper.injectMultipleSni(finalData, finalLen, mangledHost)
            finalLen = finalData.size
        }

        if (strategy == BypassStrategy.TLS_ALPN_SKEW) {
            finalData = FakePacketHelper.injectTlsGrease(finalData, finalLen)
            finalLen = finalData.size
        }

        if (strategy == BypassStrategy.TLS_CIPHER_SHUFFLE || strategy == BypassStrategy.TLS_CLIENT_HELLO_REORDER) {
            finalData = FakePacketHelper.shuffleTlsExtensions(finalData, finalLen)
            finalLen = finalData.size
        }

        if (strategy == BypassStrategy.TLS_CLIENT_HELLO_GREASE_RANDOM || strategy == BypassStrategy.TLS_GREASE_SKEW) {
            finalData = FakePacketHelper.injectTlsGrease(finalData, finalLen)
            finalLen = finalData.size
        }

        if (strategy == BypassStrategy.TLS_CLIENT_HELLO_MULTI_PAD || strategy == BypassStrategy.TLS_CLIENT_HELLO_PAD_EXTREME) {
            finalData = FakePacketHelper.injectTlsPadding(finalData, finalLen, rnd.nextInt(512, 1024))
            finalLen = finalData.size
        }

        if (strategy == BypassStrategy.TLS_CLIENT_HELLO_PAD) {
            finalData = FakePacketHelper.injectTlsPadding(finalData, finalLen, 128)
            finalLen = finalData.size
        }

        if (strategy == BypassStrategy.TLS_DIRTY) {
            val dirty = FakePacketHelper.buildUdpNoise(16)
            TtlHelper.setTtl(socket, rnd.nextInt(2, 4))
            output.write(dirty)
            output.flush()
            delay(rnd.nextLong(1, 4))
            TtlHelper.setTtl(socket, 64)
        }

        if (strategy == BypassStrategy.TLS_ECH_FAKE) {
            finalData = TlsParser.injectEchGrease(finalData, finalLen)
            finalLen = finalData.size
        }

        if (strategy == BypassStrategy.TLS_EXT_CHAOS || strategy == BypassStrategy.TLS_EXT_SKEW) {
            finalData = FakePacketHelper.shuffleTlsExtensions(finalData, finalLen)
            finalLen = finalData.size
        }

        if (strategy == BypassStrategy.TLS_HANDSHAKE_RANDOM_PADDING) {
            finalData = FakePacketHelper.injectTlsPadding(finalData, finalLen, rnd.nextInt(32, 128))
            finalLen = finalData.size
        }

        if (strategy == BypassStrategy.TLS_HELLO_JUNK) {
            val junk = FakePacketHelper.buildUdpNoise(rnd.nextInt(5, 15))
            TtlHelper.setTtl(socket, rnd.nextInt(2, 4))
            output.write(junk)
            output.flush()
            delay(rnd.nextLong(1, 3))
            TtlHelper.setTtl(socket, 64)
        }

        if (strategy == BypassStrategy.TLS_LEGACY_HELLOS) {
            if (finalLen > 10 && finalData[0] == 0x16.toByte()) {
                finalData[1] = 0x03.toByte()
                finalData[2] = 0x01.toByte()
            }
        }

        if (strategy == BypassStrategy.TLS_MULTI_SNI) {
            finalData = FakePacketHelper.injectMultipleSni(finalData, finalLen, "decoy.org, $host")
            finalLen = finalData.size
        }

        if (strategy == BypassStrategy.TLS_REHANDSHAKE_FAKE) {
            val fake = FakePacketHelper.buildRealisticTlsHello("mydecoy.org")
            output.write(fake)
            output.flush()
            delay(rnd.nextLong(5, 15))
        }

        if (strategy == BypassStrategy.TLS_SESSION_TICKET_SKEW) {
            finalData = FakePacketHelper.mangleSessionId(finalData, finalLen)
            finalLen = finalData.size
        }

        if (strategy == BypassStrategy.TLS_SNI_GREASE) {
            finalData = FakePacketHelper.injectTlsGrease(finalData, finalLen)
            finalLen = finalData.size
        }

        if (strategy == BypassStrategy.TLS_SNI_OVERLAP_SKEW || strategy == BypassStrategy.TLS_SNI_SKEW_ADVANCED) {
            finalData = FakePacketHelper.injectMultipleSni(finalData, finalLen, host.reversed())
            finalLen = finalData.size
        }

        if (strategy == BypassStrategy.TLS_GREASE || strategy == BypassStrategy.TLS_EXTENSION_GREASE) {
            finalData = FakePacketHelper.injectTlsGrease(finalData, finalLen)
            finalLen = finalData.size
        }

        if (strategy == BypassStrategy.TLS_SESSION_ID_MANGLE || strategy == BypassStrategy.TLS_SESSION_ID_RAND) {
            finalData = FakePacketHelper.mangleSessionId(finalData, finalLen)
            finalLen = finalData.size
        }

        if (strategy == BypassStrategy.TLS_CLIENT_HELLO_SHUFFLE || strategy == BypassStrategy.TLS_EXTENSION_SHUFFLE) {
            finalData = FakePacketHelper.shuffleTlsExtensions(finalData, finalLen)
            finalLen = finalData.size
        }

        if (strategy == BypassStrategy.TLS_CHROME_HELLO_FAKE || strategy == BypassStrategy.TLS_FIREFOX_HELLO_FAKE || strategy == BypassStrategy.TLS_13_HELLO_FAKE) {
            finalData = FakePacketHelper.injectTlsPadding(finalData, finalLen, 64)
            finalLen = finalData.size
        }

        if (strategy == BypassStrategy.TLS_SNI_SKEW || strategy == BypassStrategy.TLS_MIXED_CASE_SNI) {
            val skewedHost = if (rnd.nextBoolean()) host.uppercase() else host.map { if (rnd.nextBoolean()) it.uppercaseChar() else it.lowercaseChar() }.joinToString("")
            finalData = FakePacketHelper.injectMultipleSni(finalData, finalLen, skewedHost)
            finalLen = finalData.size
        }

        if (finalLen > 44 && finalData[0] == 0x16.toByte() && finalData[5] == 0x01.toByte()) {
            val sniPos = TlsParser.findSniOffset(finalData, finalLen, host = host)
            if (sniPos > 0) {
                if (strategy == BypassStrategy.TLS_SNI_SYMMETRIC_SPLIT) {
                    val split = sniPos + host.length / 2
                    output.write(finalData, 0, split)
                    output.flush()
                    delay(rnd.nextLong(2, 6))
                    output.write(finalData, split, finalLen - split)
                    output.flush()
                } else if (strategy == BypassStrategy.TLS_SNI_REVERSE) {
                    val split = sniPos
                    output.write(finalData, 0, split)
                    output.flush()
                    delay(rnd.nextLong(2, 6))
                    output.write(finalData, split, finalLen - split)
                    output.flush()
                } else {
                    val split = if (rnd.nextBoolean()) sniPos else sniPos - 1
                    output.write(finalData, 0, split)
                    output.flush()
                    delay(rnd.nextLong(2, 10))
                    output.write(finalData, split, finalLen - split)
                    output.flush()
                }
            } else {
                val part = finalLen / 3
                output.write(finalData, 0, part)
                output.flush()
                delay(rnd.nextLong(2, 8))
                output.write(finalData, part, finalLen - part)
                output.flush()
            }
        } else {
            output.write(finalData, 0, finalLen)
            output.flush()
        }
    }

    suspend fun handleFragmentationStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy, effectiveDelay: Long) {
        if (strategy == BypassStrategy.SNI_SPLIT || strategy == BypassStrategy.SNI_TRIPLE || strategy == BypassStrategy.TLS_SNI_FRAGMENT || strategy == BypassStrategy.TLS_SNI_SPLIT || strategy == BypassStrategy.TLS_SNI_JITTER_SPLIT || strategy == BypassStrategy.TLS_RECORD_FRAGMENTATION || strategy == BypassStrategy.ECH_FRAG) {
            if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                val sniPos = TlsParser.findSniOffset(data, length, host = host)
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

        if (strategy == BypassStrategy.TLS_REC_SPLIT || strategy == BypassStrategy.TLS_MULTI_FRAG) {
            var pos = 0
            val chunkSize = rnd.nextInt(8, 24)
            while (pos < length) {
                val sz = chunkSize.coerceAtMost(length - pos)
                output.write(data, pos, sz)
                output.flush()
                pos += sz
                if (pos < length) delay(effectiveDelay.coerceAtLeast(1L))
            }
            return
        }

        if (strategy == BypassStrategy.TCP_PULSE_FRAG) {
            var pos = 0
            while (pos < length) {
                val sz = rnd.nextInt(2, 64).coerceAtMost(length - pos)
                output.write(data, pos, sz)
                output.flush()
                pos += sz
                if (pos < length) delay(rnd.nextLong(1, 15))
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
        
        var pos = 0
        while (pos < length) {
            val sz = if (strategy == BypassStrategy.FRAGMENT_MULTI) {
                rnd.nextInt(16, 64).coerceAtMost(length - pos)
            } else {
                rnd.nextInt(5, 32).coerceAtMost(length - pos)
            }
            output.write(data, pos, sz)
            output.flush()
            pos += sz
            if (pos < length) {
                val delay = if (effectiveDelay > 0) effectiveDelay else rnd.nextLong(1, 10)
                delay(delay)
            }
        }
    }

    suspend fun handleAdaptiveStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy, config: SessionConfig) {
        if (strategy == BypassStrategy.TCP_COMBINED_NUCLEAR || strategy == BypassStrategy.TCP_COMBINED_HYBRID) {
            handleNuclearStrategy(socket, output, data, length, rnd, host, config)
            return
        }
        if (strategy == BypassStrategy.TLS_0RTT_FAKE) {
            handleZeroRttSimulation(socket, output, data, length, rnd, host)
            return
        }
        
        if (strategy == BypassStrategy.BYEBYEDPI_EXTREME || strategy == BypassStrategy.BYEBYEDPI_HYBRID) {
            handleByeByeDpiExtreme(socket, output, data, length, rnd, host, config)
            return
        }
        
        if (strategy == BypassStrategy.ZAPRET_EXTREME) {
            handleZapretExtreme(socket, output, data, length, rnd, host, config)
            return
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

    private suspend fun sendDecoyStorm(socket: Socket, out: OutputStream, rnd: ThreadLocalRandom, host: String, config: SessionConfig) {
        try {
            val configuredTtl = config.fakeTtl
            val fakeTtl = configuredTtl.takeIf { it > 0 } ?: AutoTtlProber.getDiscoveredTtl(host) ?: rnd.nextInt(3, 7)
            
            // Multiple decoys in sequence to exhaust stateful inspection
            val decoys = listOf(
                FakePacketHelper.buildRealisticHttp2Header(),
                FakePacketHelper.buildRealisticTlsHello("blocked.content.internal"),
                FakePacketHelper.buildHttpChaosPacket(),
                FakePacketHelper.buildStunBindingRequest(),
                FakePacketHelper.buildRealisticTlsHello(host).also { 
                    if (it.size > 10) it[it.size-1] = rnd.nextInt().toByte() // Corrupt slightly
                }
            ).shuffled()

            for (decoy in decoys.take(rnd.nextInt(3, 5))) {
                TtlHelper.setTtl(socket, fakeTtl)
                out.write(decoy)
                out.flush()
                delay(rnd.nextLong(1, 4))
            }
            TtlHelper.setTtl(socket, 64) // Restore normal TTL
        } catch (e: Throwable) {
            // Log.v("StrategyHandlers", "Decoy storm failed: ${e.message}")
        }
    }

    private suspend fun handleByeByeDpiExtreme(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, config: SessionConfig) {
        ProxyStats.logTraffic("Triggering ByeByeDPI Extreme for $host")
        // Inspired by ByeByeDPI: sequence of out-of-order and ghost segments
        val intensity = ProxyStats.censorshipIntensity.value
        val sniPos = TlsParser.findSniOffset(data, length, host = host)
        val splitPos = if (sniPos > 0) sniPos else (length / 2).coerceAtLeast(1)
        
        // 1. Send OOB/Urgent noise to confuse stateful DPI
        if (intensity > 70) {
            try { socket.sendUrgentData(rnd.nextInt(1, 255)) } catch (e: Throwable) {}
        }
        
        // 2. Ghost Disorder: Send second half with low TTL first
        val fakeTtl = config.fakeTtl.takeIf { it > 0 } ?: AutoTtlProber.getDiscoveredTtl(host) ?: rnd.nextInt(2, 5)
        TtlHelper.setTtl(socket, fakeTtl)
        output.write(data, splitPos, length - splitPos)
        output.flush()
        delay(rnd.nextLong(2, 10))
        
        // 3. Real First Half
        TtlHelper.setTtl(socket, 64)
        output.write(data, 0, splitPos)
        output.flush()
        delay(rnd.nextLong(5, 15))
        
        // 4. Real Second Half
        output.write(data, splitPos, length - splitPos)
        output.flush()
    }

    private suspend fun handleZapretExtreme(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, config: SessionConfig) {
        ProxyStats.logTraffic("Triggering Zapret Extreme for $host")
        // Inspired by Zapret: combine header mangling with extreme fragmentation
        val intensity = ProxyStats.censorshipIntensity.value
        
        if (TlsParser.isClientHello(data, length)) {
            // Extreme fragmentation for TLS
            var pos = 0
            while (pos < length) {
                val sz = if (pos == 0) rnd.nextInt(1, 5) else rnd.nextInt(5, 40)
                val chunk = sz.coerceAtMost(length - pos)
                
                // Inject fake retransmission occasionally
                if (intensity > 80 && rnd.nextInt(100) < 20) {
                    TtlHelper.setTtl(socket, 2)
                    output.write(data, pos, chunk)
                    output.flush()
                    delay(2)
                    TtlHelper.setTtl(socket, 64)
                }
                
                output.write(data, pos, chunk)
                output.flush()
                pos += chunk
                if (pos < length) delay(rnd.nextLong(5, 20))
            }
        } else {
            // Generic fallback
            output.write(data, 0, length)
            output.flush()
        }
    }

    private suspend fun handleNuclearStrategy(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, config: SessionConfig) {
        ProxyStats.logTraffic("Triggering NUCLEAR bypass for $host")
        // Multi-stage fragmentation with desync, window oscillation and fake retransmissions
        val intensity = ProxyStats.censorshipIntensity.value
        val sniPos = TlsParser.findSniOffset(data, length, host = host)
        val splitPos = if (sniPos > 0) sniPos else (length / 2).coerceAtLeast(1)
        
        // 1. Initial desync: Set tiny window
        TtlHelper.setWindowSize(socket, rnd.nextInt(1, 20))
        
        // 2. Heavy Decoy Storm
        sendDecoyStorm(socket, output, rnd, host, config)
        
        // 3. Fragmentation with overlapping segments (in extreme cases)
        if (intensity > 90 && length > splitPos + 2) {
            // Overlap: Send bytes [0..splitPos] then [splitPos-1..splitPos+1] then [splitPos..end]
            output.write(data, 0, splitPos)
            output.flush()
            delay(rnd.nextLong(5, 15))
            
            TtlHelper.setTtl(socket, rnd.nextInt(2, 4)) // Fake TTL for overlap
            output.write(data, splitPos - 1, 2)
            output.flush()
            delay(rnd.nextLong(2, 5))
            TtlHelper.setTtl(socket, 64)
            
            output.write(data, splitPos, length - splitPos)
            output.flush()
        } else {
            // Standard split at SNI
            output.write(data, 0, splitPos)
            output.flush()
            delay(config.delay1.coerceAtLeast(15L))
            
            // Further fragment the second half
            var pos = splitPos
            while (pos < length) {
                val sz = if (intensity > 70) rnd.nextInt(1, 32) else rnd.nextInt(32, 256)
                val currentChunk = sz.coerceAtMost(length - pos)
                output.write(data, pos, currentChunk)
                output.flush()
                pos += currentChunk
                if (pos < length) delay(rnd.nextLong(2, 10))
            }
        }
        
        // 4. Restore window
        TtlHelper.setWindowSize(socket, 65535)
    }

    private suspend fun handleZeroRttSimulation(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String) {
        // Simulate TLS 1.3 0-RTT by sending data immediately after ClientHello in the same stream
        // but with a fake session ticket extension (simplified simulation)
        output.write(data, 0, length)
        output.flush()
        // Inject some "resumption" noise
        val noise = FakePacketHelper.buildUdpNoise(rnd.nextInt(32, 128))
        delay(rnd.nextLong(1, 3))
        output.write(noise)
        output.flush()
    }

    private suspend fun handleQuicChaos(socket: DatagramSocket, packet: DatagramPacket, rnd: ThreadLocalRandom) {
        val dest = packet.address
        val port = packet.port
        
        // 1. UDP Noise Injection (Chaff)
        repeat(rnd.nextInt(1, 4)) {
            val noise = FakePacketHelper.buildUdpNoise(rnd.nextInt(10, 100))
            val p = DatagramPacket(noise, noise.size, dest, port)
            TtlHelper.setUdpTtl(socket, AutoTtlProber.getDiscoveredTtl(dest.hostAddress ?: "") ?: rnd.nextInt(2, 6)) // Low TTL decoy
            try { socket.send(p) } catch (e: Throwable) {}
        }
        
        // 2. IP ID and TTL randomization for the real packet
        TtlHelper.setUdpTtl(socket, 64)
        
        // 3. Optional "Stutter" delay for handshake packets
        if (packet.length > 1000 && packet.port == 443) {
            delay(rnd.nextLong(1, 5))
        }
        
        socket.send(packet)
    }

    suspend fun handleUdpStrategies(
        socket: DatagramSocket,
        packet: DatagramPacket,
        rnd: ThreadLocalRandom,
        host: String,
        strategy: BypassStrategy,
        config: SessionConfig
    ) {
        if (strategy == BypassStrategy.PROTOCOL_CONFUSION_QUIC) {
            val fake = FakePacketHelper.buildQuicInitialFake()
            writeUdpWithFake(socket, packet.address, packet.port, fake, packet, config)
            return
        }

        if (strategy == BypassStrategy.QUIC_HANDSHAKE_SKEW) {
            val paddingSize = rnd.nextInt(32, 128)
            val padded = FakePacketHelper.buildQuicJitterPad(packet.length + paddingSize)
            System.arraycopy(packet.data, packet.offset, padded, 0, packet.length)
            val skewPacket = DatagramPacket(padded, padded.size, packet.address, packet.port)
            socket.send(skewPacket)
            delay(rnd.nextLong(3, 15))
            return
        }

        if (strategy == BypassStrategy.PROTOCOL_CONFUSION_DTLS || strategy == BypassStrategy.UDP_FAKE_DTLS) {
            val fake = FakePacketHelper.buildFakeDtlsClientHello()
            writeUdpWithFake(socket, packet.address, packet.port, fake, packet, config)
            return
        }

        if (strategy == BypassStrategy.UDP_FAKE_SESSION) {
            val fake = FakePacketHelper.buildUdpNoise(rnd.nextInt(20, 60))
            writeUdpWithFake(socket, packet.address, packet.port, fake, packet, config)
            return
        }

        if (strategy == BypassStrategy.UDP_NOISE_PAD || strategy == BypassStrategy.UDP_PADDING_CHAOS || strategy == BypassStrategy.UDP_QUIC_PAD || strategy == BypassStrategy.UDP_QUIC_JITTER_PAD) {
            val paddedData = packet.data.copyOf(packet.length + rnd.nextInt(16, 64))
            val p = DatagramPacket(paddedData, paddedData.size, packet.address, packet.port)
            socket.send(p)
            return
        }

        if (strategy == BypassStrategy.QUIC_INITIAL_FAKE || strategy == BypassStrategy.QUIC_INITIAL_PADDING_EXTREME) {
            val fake = FakePacketHelper.buildQuicInitialFake()
            writeUdpWithFake(socket, packet.address, packet.port, fake, packet, config)
            return
        }

        if (strategy == BypassStrategy.UDP_HIGH_VOL_PACING || strategy == BypassStrategy.UDP_STUTTER) {
            delay(rnd.nextLong(2, 8))
            socket.send(packet)
            return
        }

        if (strategy == BypassStrategy.UDP_ZERO_LEN_SKEW) {
            val empty = DatagramPacket(ByteArray(0), 0, packet.address, packet.port)
            try { socket.send(empty) } catch (e: Throwable) {}
            delay(rnd.nextLong(1, 3))
            socket.send(packet)
            return
        }

        if (strategy == BypassStrategy.UDP_NOISE_CHAOS || strategy == BypassStrategy.UDP_BURST_CHAOS) {
            repeat(rnd.nextInt(2, 5)) {
                val noise = FakePacketHelper.buildUdpNoise(rnd.nextInt(10, 50))
                val p = DatagramPacket(noise, noise.size, packet.address, packet.port)
                try { socket.send(p) } catch (e: Throwable) {}
            }
            socket.send(packet)
            return
        }

        if (strategy == BypassStrategy.UDP_QUIC_SKEW || strategy == BypassStrategy.UDP_SKEW_ADVANCED || strategy == BypassStrategy.UDP_SKEW_REVERSE) {
            delay(rnd.nextLong(1, 5))
            socket.send(packet)
            return
        }

        if (strategy == BypassStrategy.UDP_DATA_FRAG || strategy == BypassStrategy.UDP_IP_FRAG || strategy == BypassStrategy.UDP_IPv6_FRAG || strategy == BypassStrategy.QUIC_INITIAL_FRAGMENTATION || strategy == BypassStrategy.QUIC_INITIAL_FRAGMENT || strategy == BypassStrategy.QUIC_FORCE_FRAG || strategy == BypassStrategy.UDP_FRAGMENT_SKEW) {
            if (packet.length > 100) {
                val part1 = packet.data.copyOfRange(0, packet.length / 2)
                val part2 = packet.data.copyOfRange(packet.length / 2, packet.length)
                val p1 = DatagramPacket(part1, part1.size, packet.address, packet.port)
                val p2 = DatagramPacket(part2, part2.size, packet.address, packet.port)
                try { socket.send(p1) } catch (e: Throwable) {}
                delay(rnd.nextLong(1, 4))
                try { socket.send(p2) } catch (e: Throwable) {}
            } else {
                socket.send(packet)
            }
            return
        }

        if (strategy == BypassStrategy.UDP_FAKE_TRAFFIC || strategy == BypassStrategy.UDP_REPLICATION) {
            socket.send(packet)
            try { socket.send(packet) } catch (e: Throwable) {}
            return
        }

        if (strategy == BypassStrategy.UDP_GHOST_SKEW) {
            val ghost = FakePacketHelper.buildUdpNoise(rnd.nextInt(16, 32))
            writeUdpWithFake(socket, packet.address, packet.port, ghost, packet, config)
            return
        }

        if (strategy == BypassStrategy.QUIC_RST_SKEW || strategy == BypassStrategy.QUIC_MTU_PROBE || strategy == BypassStrategy.QUIC_VERSION_SKEW) {
            val fakeQuic = FakePacketHelper.buildQuicInitialFake()
            writeUdpWithFake(socket, packet.address, packet.port, fakeQuic, packet, config)
            return
        }

        if (strategy == BypassStrategy.DNS_OVER_TCP || strategy == BypassStrategy.DNS_OVER_TCP_FORCE || strategy == BypassStrategy.DNS_OVER_QUIC) {
            socket.send(packet)
            return
        }

        if (strategy == BypassStrategy.DNS_NOISE || strategy == BypassStrategy.DNS_CASE_MANGLE) {
            val fakeDns = FakePacketHelper.buildDnsFakeQuery("decoy.internal")
            val ghost = DatagramPacket(fakeDns, fakeDns.size, packet.address, packet.port)
            try { socket.send(ghost) } catch (e: Throwable) {}
            delay(rnd.nextLong(1, 3))
            socket.send(packet)
            return
        }

        if (strategy == BypassStrategy.UDP_HEARTBEAT) {
            val ping = "PING".toByteArray()
            val pingP = DatagramPacket(ping, ping.size, packet.address, packet.port)
            try { socket.send(pingP) } catch (e: Throwable) {}
            delay(rnd.nextLong(1, 3))
            socket.send(packet)
            return
        }

        if (strategy == BypassStrategy.UDP_REORDER) {
            delay(rnd.nextLong(2, 6))
            socket.send(packet)
            return
        }

        if (strategy == BypassStrategy.UDP_IP_ID_MANGLE) {
            socket.send(packet)
            return
        }

        if (strategy == BypassStrategy.UDP_QUIC_SMART_SHADOW) {
            val shadow = FakePacketHelper.buildQuicInitialFake()
            writeUdpWithFake(socket, packet.address, packet.port, shadow, packet, config)
            return
        }

        if (strategy == BypassStrategy.UDP_DNS_REORDER_HYBRID) {
            socket.send(packet)
            return
        }

        if (strategy == BypassStrategy.UDP_FAKE_PACKET) {
            val fake = FakePacketHelper.buildQuicInitialFake()
            writeUdpWithFake(socket, packet.address, packet.port, fake, packet, config)
            return
        }

        if (strategy == BypassStrategy.UDP_FRAGMENTATION) {
            val data = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
            if (data.size > 2) {
                val mid = data.size / 2
                val p1 = DatagramPacket(data, 0, mid, packet.address, packet.port)
                val p2 = DatagramPacket(data, mid, data.size - mid, packet.address, packet.port)
                socket.send(p1)
                delay(rnd.nextLong(1, 10))
                socket.send(p2)
            } else {
                socket.send(packet)
            }
            return
        }

        if (strategy == BypassStrategy.UDP_OVERLAP_SKEW) {
            // Send empty junk then real packet
            val junk = DatagramPacket(ByteArray(1), 1, packet.address, packet.port)
            TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5))
            try { socket.send(junk) } catch (e: Throwable) {}
            TtlHelper.setUdpTtl(socket, 64)
            delay(rnd.nextLong(1, 5))
            socket.send(packet)
            return
        }

        if (strategy == BypassStrategy.UDP_COMBINED_HYBRID || strategy == BypassStrategy.UDP_COMBINED_NUCLEAR || strategy == BypassStrategy.ADAPTIVE_CHUNK || strategy == BypassStrategy.BYEBYEDPI_SIM || strategy == BypassStrategy.BYEBYEDPI_HYBRID || strategy == BypassStrategy.BYEBYEDPI_EXTREME || strategy == BypassStrategy.ZAPRET_EXTREME || strategy == BypassStrategy.CHAOS) {
            handleQuicChaos(socket, packet, rnd)
            return
        }

        if (strategy == BypassStrategy.UDP_QUIC_CHAOS) {
            handleQuicChaos(socket, packet, rnd)
            return
        }
        
        if (strategy == BypassStrategy.UDP_TELEGRAM_FAKE) {
            val fake = FakePacketHelper.buildTelegramFake()
            writeUdpWithFake(socket, packet.address, packet.port, fake, packet, config)
            return
        }
        
        if (strategy == BypassStrategy.UDP_DISCORD_FAKE) {
            val fake = FakePacketHelper.buildDiscordFake()
            writeUdpWithFake(socket, packet.address, packet.port, fake, packet, config)
            return
        }

        if (strategy == BypassStrategy.UDP_STUN_FAKE) {
            val fake = FakePacketHelper.buildStunBindingRequest()
            writeUdpWithFake(socket, packet.address, packet.port, fake, packet, config)
            return
        }

        if (strategy == BypassStrategy.UDP_WIREGUARD_FAKE) {
            val fake = FakePacketHelper.buildWireguardFake()
            writeUdpWithFake(socket, packet.address, packet.port, fake, packet, config)
            return
        }

        if (strategy == BypassStrategy.UDP_IKE_FAKE) {
            val fake = FakePacketHelper.buildIkeHandshake()
            writeUdpWithFake(socket, packet.address, packet.port, fake, packet, config)
            return
        }

        if (strategy == BypassStrategy.UDP_DHCP_FAKE) {
            val fake = FakePacketHelper.buildDhcpRequest()
            writeUdpWithFake(socket, packet.address, packet.port, fake, packet, config)
            return
        }
        
        // UDP allows fake packets safely
        if (packet.length > 30) {
            val fakeQuic = FakePacketHelper.buildQuicInitialFake()
            val ghost = DatagramPacket(fakeQuic, fakeQuic.size, packet.address, packet.port)
            TtlHelper.setUdpTtl(socket, config.fakeTtl.takeIf { it > 0 } ?: AutoTtlProber.getDiscoveredTtl(host) ?: rnd.nextInt(2, 6))
            try { socket.send(ghost) } catch (e: Throwable) {}
            TtlHelper.setUdpTtl(socket, 64)
            delay(rnd.nextLong(1, 4))
        }
        socket.send(packet)
    }

    suspend fun handleUdpPacketWithEvasion(
        socket: DatagramSocket,
        packet: DatagramPacket,
        strategy: BypassStrategy,
        intensity: Int,
        rnd: ThreadLocalRandom,
        host: String,
        config: SessionConfig
    ) {
        val data = packet.data
        val length = packet.length
        val address = packet.address
        val port = packet.port
        
        when (strategy) {
            BypassStrategy.UDP_FAKE_PACKET -> {
                val fake = if (rnd.nextBoolean()) FakePacketHelper.buildQuicInitialFake() else FakePacketHelper.buildDhcpRequest()
                writeUdpWithFake(socket, address, port, fake, packet, config)
            }
            BypassStrategy.UDP_FRAGMENTATION -> {
                if (length > 100) {
                    val split = length / 2
                    val p1 = DatagramPacket(data, split, address, port)
                    val p2 = DatagramPacket(data, split, length - split, address, port)
                    socket.send(p1)
                    delay(rnd.nextLong(2, 10))
                    socket.send(p2)
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.UDP_OVERLAP_SKEW -> {
                if (length > 200) {
                    val part1 = length / 3
                    val overlap = rnd.nextInt(10, 30)
                    
                    val p1 = DatagramPacket(data, part1 + overlap, address, port)
                    socket.send(p1)
                    delay(rnd.nextLong(1, 5))
                    
                    val p2 = DatagramPacket(data, part1, length - part1, address, port)
                    socket.send(p2)
                } else {
                    socket.send(packet)
                }
            }
            else -> {
                if (intensity > 60 && rnd.nextInt(100) < 30) {
                    val fake = FakePacketHelper.buildQuicInitialFake()
                    writeUdpWithFake(socket, address, port, fake, packet, config)
                } else {
                    socket.send(packet)
                }
            }
        }
    }

    suspend fun writeUdpWithFake(
        socket: DatagramSocket,
        targetAddr: InetAddress,
        targetPort: Int,
        fakeData: ByteArray,
        realPacket: DatagramPacket,
        config: SessionConfig
    ) {
        val ghost = DatagramPacket(fakeData, fakeData.size, targetAddr, targetPort)
        TtlHelper.setUdpTtl(socket, config.fakeTtl.takeIf { it > 0 } ?: AutoTtlProber.getDiscoveredTtl(targetAddr.hostAddress ?: "") ?: 3)
        try { socket.send(ghost) } catch (e: Throwable) {}
        TtlHelper.setUdpTtl(socket, 64)
        delay(config.delay1)
        socket.send(realPacket)
    }

    suspend fun handleTimingStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy) {
        if (strategy == BypassStrategy.SLOW_SEND) {
            var pos = 0
            while (pos < length) {
                val sz = rnd.nextInt(1, 3).coerceAtMost(length - pos)
                output.write(data, pos, sz)
                output.flush()
                pos += sz
                if (pos < length) delay(rnd.nextLong(10, 30))
            }
            return
        }

        if (strategy == BypassStrategy.TCP_ACK_DELAY) {
            val part = (length / 4).coerceAtLeast(1)
            output.write(data, 0, part)
            output.flush()
            delay(rnd.nextLong(30, 80))
            output.write(data, part, length - part)
            output.flush()
            return
        }

        // Default timing strategy
        var pos = 0
        while (pos < length) {
            val sz = rnd.nextInt(4, 16).coerceAtMost(length - pos)
            output.write(data, pos, sz)
            output.flush()
            pos += sz
            if (pos < length) delay(rnd.nextLong(5, 15))
        }
    }

    fun isProbableHttp(data: ByteArray, length: Int): Boolean {
        if (length < 10) return false
        val s = String(data, 0, minOf(length, 10), Charsets.US_ASCII)
        return s.startsWith("GET ") || s.startsWith("POST ") || s.startsWith("HEAD ") || s.startsWith("PUT ") || s.startsWith("CONNECT ")
    }

    fun findHeaderEnd(data: ByteArray, length: Int): Int {
        for (i in 0 until length - 3) {
            if (data[i] == '\r'.code.toByte() && data[i+1] == '\n'.code.toByte() && data[i+2] == '\r'.code.toByte() && data[i+3] == '\n'.code.toByte()) {
                return i + 4
            }
        }
        return -1
    }
}
