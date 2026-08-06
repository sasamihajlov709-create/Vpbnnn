package com.aistudio.pinkproxy.fresh

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ThreadLocalRandom
import kotlinx.coroutines.delay

object UdpStrategyHandlers {

    suspend fun handleUdpStrategies(
        socket: DatagramSocket,
        packet: DatagramPacket,
        rnd: ThreadLocalRandom,
        host: String,
        strategy: BypassStrategy,
        config: SessionConfig
    ) {
        val data = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
        UdpStrategyHandler.handleUdpStrategies(
            socket, packet.address, packet.port, data, packet.length, rnd, host, strategy
        )
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
        handleUdpStrategies(socket, packet, rnd, host, strategy, config)
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
        TtlHelper.setUdpTtl(socket, BypassConfig.currentTtl)
        delay(config.delay1)
        socket.send(realPacket)
    }
}
