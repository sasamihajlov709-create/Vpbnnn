package com.aistudio.pinkproxy.fresh

import java.net.Socket
import java.net.DatagramSocket
import java.util.Random
import java.util.concurrent.ThreadLocalRandom

object StrategyUtils {
    private val rnd = Random()

    fun setTtl(socket: Socket, ttl: Int) {
        TtlHelper.setTtl(socket, ttl)
    }

    fun setUdpTtl(socket: DatagramSocket, ttl: Int) {
        TtlHelper.setUdpTtl(socket, ttl)
    }

    fun getSmallNoise(size: Int): ByteArray {
        return FakePacketHelper.getSmallNoise(size)
    }

    fun getFakeTtl(host: String, rnd: Random): Int {
        return if (BypassConfig.fakeTtl > 0) BypassConfig.fakeTtl else rnd.nextInt(3, 7)
    }

    fun getFakeTtl(host: String, rnd: ThreadLocalRandom): Int {
        return if (BypassConfig.fakeTtl > 0) BypassConfig.fakeTtl else rnd.nextInt(3, 7)
    }

    fun getRealisticTlsHello(host: String): ByteArray {
        return FakePacketHelper.buildRealisticTlsHello(host)
    }

    fun getDelayedWriter(socket: Socket) = socket.getOutputStream()
}
