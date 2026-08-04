package com.aistudio.pinkproxy.fresh

import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom
import kotlinx.coroutines.delay

object StrategyHandlers {

    suspend fun handleHttpStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy) {
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

        val str = if (strategy == BypassStrategy.HTTP_HOST_SMUGGLE || 
                      strategy == BypassStrategy.HTTP_HOST_REORDER || 
                      strategy == BypassStrategy.HTTP_KEEP_ALIVE_FAKE) {
            String(data, 0, length, Charsets.US_ASCII)
        } else null

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
        if (strategy == BypassStrategy.PROTOCOL_CONFUSION_HTTP) {
            val fakeTls = FakePacketHelper.buildRealisticTlsHello(host)
            output.write(fakeTls)
            output.flush()
            delay(rnd.nextLong(2, 5))
        }

        val dataCopy = data.copyOfRange(0, length)
        
        if (length > 10 && rnd.nextInt(100) < 30) {
            val spaceIndex = dataCopy.indexOf(' '.code.toByte())
            if (spaceIndex in 1..8) {
                val charIndex = rnd.nextInt(0, spaceIndex)
                dataCopy[charIndex] = (dataCopy[charIndex].toInt() xor 32).toByte()
            }
        }

        val part = length / 2
        if (length > 10) {
            output.write(dataCopy, 0, part)
            output.flush()
            delay(rnd.nextLong(2, 5))
            output.write(dataCopy, part, length - part)
            output.flush()
        } else {
            output.write(dataCopy, 0, length)
            output.flush()
        }
    }

    suspend fun handleTcpStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy) {
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
        
        if (strategy == BypassStrategy.ECH_GREASE || strategy == BypassStrategy.ECH_FRAG) {
            finalData = TlsParser.injectEchGrease(data, length)
            finalLen = finalData.size
        }

        if (finalLen > 44 && finalData[0] == 0x16.toByte() && finalData[5] == 0x01.toByte()) {
            // Find SNI position if possible
            val sniPos = TlsParser.findSniOffset(finalData, finalLen, host)
            if (sniPos > 0) {
                // Split exactly at SNI or just before
                val split = if (rnd.nextBoolean()) sniPos else sniPos - 1
                output.write(finalData, 0, split)
                output.flush()
                delay(rnd.nextLong(2, 10))
                output.write(finalData, split, finalLen - split)
                output.flush()
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
        if (strategy == BypassStrategy.SNI_SPLIT || strategy == BypassStrategy.SNI_TRIPLE) {
            if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                val sniPos = TlsParser.findSniOffset(data, length, host)
                if (sniPos > 0) {
                    val split1 = sniPos - rnd.nextInt(1, 3)
                    if (split1 > 0) {
                        output.write(data, 0, split1)
                        output.flush()
                        delay(effectiveDelay.coerceAtLeast(1L))
                        
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
        
        var pos = 0
        while (pos < length) {
            val sz = rnd.nextInt(5, 20).coerceAtMost(length - pos)
            output.write(data, pos, sz)
            output.flush()
            pos += sz
            if (pos < length) delay(effectiveDelay.coerceAtLeast(1L))
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
        // Multi-stage fragmentation with desync, window oscillation and fake retransmissions
        val intensity = ProxyStats.censorshipIntensity.value
        val splitPos = TlsParser.findSniOffset(data, length, host).coerceAtLeast(length / 2).coerceAtMost(length - 1)
        
        // 1. Initial desync: Set tiny window
        TtlHelper.setWindowSize(socket, rnd.nextInt(1, 10))
        
        // 2. Send first fragment (pre-SNI) with low TTL decoy if high intensity
        if (intensity > 85) {
            val decoy = FakePacketHelper.buildRealisticTlsHello("decoy.internal")
            TtlHelper.setTtl(socket, config.fakeTtl.takeIf { it > 0 } ?: AutoTtlProber.getDiscoveredTtl(host) ?: rnd.nextInt(2, 6))
            output.write(decoy)
            output.flush()
            delay(rnd.nextLong(2, 5))
            TtlHelper.setTtl(socket, 64)
        }
        
        output.write(data, 0, splitPos)
        output.flush()
        
        // 3. Staggered fragmentation of the rest
        delay(config.delay1.coerceAtLeast(10L))
        TtlHelper.setWindowSize(socket, 65535)
        
        var pos = splitPos
        while (pos < length) {
            val sz = rnd.nextInt(1, 16).coerceAtMost(length - pos)
            output.write(data, pos, sz)
            output.flush()
            pos += sz
            if (pos < length) delay(rnd.nextLong(1, 5))
        }
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

        if (strategy == BypassStrategy.PROTOCOL_CONFUSION_DTLS) {
            val fake = FakePacketHelper.buildFakeDtlsClientHello()
            writeUdpWithFake(socket, packet.address, packet.port, fake, packet, config)
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
