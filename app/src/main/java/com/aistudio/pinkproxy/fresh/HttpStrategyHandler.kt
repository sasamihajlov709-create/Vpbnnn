package com.aistudio.pinkproxy.fresh

import java.io.OutputStream
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom
import kotlinx.coroutines.delay

object HttpStrategyHandler {
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
            TtlHelper.setTtl(socket, StrategyUtils.getFakeTtl(host, rnd))
            output.write(fakeReq)
            output.flush()
            delay(rnd.nextLong(2, 6))
            TtlHelper.setTtl(socket, BypassConfig.currentTtl)
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.HTTP2_PREAMBLE_FAKE) {
            val preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray()
            val fakeSettings = byteArrayOf(0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00)
            TtlHelper.setTtl(socket, StrategyUtils.getFakeTtl(host, rnd))
            output.write(preface)
            output.write(fakeSettings)
            output.flush()
            delay(rnd.nextLong(1, 4))
            TtlHelper.setTtl(socket, BypassConfig.currentTtl)
            output.write(data, 0, length)
            output.flush()
            return
        }

        if (strategy == BypassStrategy.TCP_REARRANGE_CHUNKS) {
            if (length > 100) {
                val c1Size = length / 3
                val c2Size = length / 3
                val c3Size = length - c1Size - c2Size
                
                val fakeTtl = StrategyUtils.getFakeTtl(host, rnd)
                
                TtlHelper.setTtl(socket, fakeTtl)
                output.write(data, 0, c1Size)
                output.flush()
                delay(rnd.nextLong(2, 5))
                
                output.write(data, 0, c1Size + c2Size)
                output.flush()
                delay(rnd.nextLong(2, 5))
                
                TtlHelper.setTtl(socket, BypassConfig.currentTtl)
                output.write(data, 0, c1Size)
                output.flush()
                delay(rnd.nextLong(1, 3))
                
                output.write(data, c1Size, c2Size)
                output.flush()
                delay(rnd.nextLong(1, 3))
                
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

        val str = if (strategy.name.startsWith("HTTP_")) {
            String(data, 0, length, Charsets.US_ASCII)
        } else null

        if (str != null) {
            val modified = when(strategy) {
                BypassStrategy.HTTP_AUTH_RANDOM -> str.replace("Host: $host", "Host: $host\r\nAuthorization: Basic " + android.util.Base64.encodeToString(FakePacketHelper.buildUdpNoise(12), android.util.Base64.NO_WRAP))
                BypassStrategy.HTTP_CONNECTION_CLOSE_SKEW -> str.replace("Host: $host", "Host: $host\r\nCoNnEcTiOn: ClOsE")
                BypassStrategy.HTTP_HEADER_FUZZING -> str.replace("Host: $host", "Host: $host\r\nX-Fuzzed-Header-" + rnd.nextInt(100) + ": " + rnd.nextInt(1000000))
                BypassStrategy.HTTP_HEADER_MANGLE -> str.replace("Accept:", "AcCePt: ")
                BypassStrategy.HTTP_HOST_DOT_MANGLE -> str.replace("Host: $host", "Host: $host.")
                BypassStrategy.HTTP_HOST_REVERSE -> str.replace("Host: $host", "Host: " + host.reversed())
                BypassStrategy.HTTP_LINE_SPLIT -> str.replace("\r\n", "\r\n ")
                BypassStrategy.HTTP_METHOD_SPACE_MANGLE -> str.replace("GET ", "GET\t").replace("POST ", "POST\t")
                BypassStrategy.HTTP_RANGE_SKEW -> str.replace("Host: $host", "Host: $host\r\nRange: bytes=0-0")
                BypassStrategy.HTTP_USER_AGENT_SKEW -> str.replace("User-Agent:", "UsEr-AgEnT:")
                BypassStrategy.HTTP_HOST_SMUGGLE -> if (str.contains("Host:")) str.replaceFirst("Host: $host", "Host: mydecoy.com\r\nHost: $host") else str
                BypassStrategy.HTTP_HOST_SPACE -> str.replace("Host: $host", "Host:  $host")
                BypassStrategy.HTTP_VERSION_SKEW -> str.replace("HTTP/1.1", "HTTP/1.2")
                BypassStrategy.HTTP_HOST_TAB_MANGLE -> str.replace("Host: $host", "Host:\t$host")
                BypassStrategy.HTTP_MULTI_LINE_MANGLE, BypassStrategy.HTTP_HOST_FOLDING -> str.replace("Host: $host", "Host:\r\n  $host")
                BypassStrategy.HTTP_HOST_MANGLE, BypassStrategy.HTTP_HOST_CASE_MANGLE -> {
                    val mixedHostHeader = if (rnd.nextBoolean()) "hOsT: $host" else "Host: " + host.uppercase()
                    str.replace("Host: $host", mixedHostHeader)
                }
                BypassStrategy.HTTP_KEEP_ALIVE_FAKE -> str.replace("Connection: keep-alive", "Connection: keep-alive, Upgrade")
                BypassStrategy.HTTP_HOST_REORDER -> {
                    val hostHeader = "Host: $host\r\n"
                    if (str.contains(hostHeader)) {
                        val smuggled = str.replaceFirst(hostHeader, "")
                        val endOfHeaders = smuggled.indexOf("\r\n\r\n")
                        if (endOfHeaders != -1) {
                            smuggled.substring(0, endOfHeaders + 2) + hostHeader + smuggled.substring(endOfHeaders + 2)
                        } else str
                    } else str
                }
                else -> null
            }
            if (modified != null) {
                val outData = modified.toByteArray()
                output.write(outData, 0, outData.size)
                output.flush()
                return
            }
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
}
