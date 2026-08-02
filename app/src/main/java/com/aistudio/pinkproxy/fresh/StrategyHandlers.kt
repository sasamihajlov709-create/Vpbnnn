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
        if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
            val part = length / 3
            output.write(data, 0, part)
            output.flush()
            delay(rnd.nextLong(2, 8))
            output.write(data, part, length - part)
            output.flush()
        } else {
            output.write(data, 0, length)
            output.flush()
        }
    }

    suspend fun handleFragmentationStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy, effectiveDelay: Long) {
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

    suspend fun handleUdpStrategies(
        socket: DatagramSocket,
        packet: DatagramPacket,
        rnd: ThreadLocalRandom,
        host: String,
        strategy: BypassStrategy,
        config: SessionConfig
    ) {
        // UDP allows fake packets safely
        if (packet.length > 30) {
            val fakeQuic = FakePacketHelper.buildQuicInitialFake()
            val ghost = DatagramPacket(fakeQuic, fakeQuic.size, packet.address, packet.port)
            TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5))
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
        TtlHelper.setUdpTtl(socket, 3)
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
