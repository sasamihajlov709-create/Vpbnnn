package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ThreadLocalRandom

object UdpTransportManager {

    fun createProtectedSocket(vpnService: VpnService): DatagramSocket {
        val s = DatagramSocket()
        try {
            vpnService.protect(s)
            // Optimize UDP buffer sizes for smooth voice (Discord/Telegram) and low-jitter video packets
            s.receiveBufferSize = 256 * 1024 // 256 KB buffer to prevent packet drop on burst
            s.sendBufferSize = 256 * 1024
        } catch (e: Throwable) {
            Log.e("UdpTransportManager", "Failed to configure UDP socket: ${e.message}")
        }
        return s
    }

    suspend fun sendUdpHeartbeat(socket: DatagramSocket, targetHost: String, targetPort: Int) {
        try {
            val rnd = ThreadLocalRandom.current()
            val addr = InetAddress.getByName(targetHost)
            val noise = if (targetPort == 443) {
                FakePacketHelper.buildUdpNoise(rnd.nextInt(1, 10))
            } else {
                byteArrayOf(0x00)
            }
            socket.send(DatagramPacket(noise, noise.size, addr, targetPort))
        } catch (e: Throwable) {
            Log.v("UdpTransportManager", "UDP heartbeat failed for $targetHost:$targetPort: ${e.message}")
        }
    }
}
