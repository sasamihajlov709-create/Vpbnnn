package com.aistudio.pinkproxy.fresh

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ThreadLocalRandom
import kotlinx.coroutines.delay

object UdpStrategyHandler {
    suspend fun handleUdpStrategies(socket: DatagramSocket, address: InetAddress, port: Int, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy) {
        if (strategy == BypassStrategy.DIRECT) {
            socket.send(DatagramPacket(data, length, address, port))
            return
        }

        when (strategy) {
            BypassStrategy.UDP_STUN_FAKE -> {
                val stun = FakePacketHelper.buildStunBindingRequest()
                socket.send(DatagramPacket(stun, stun.size, address, port))
                delay(rnd.nextLong(1, 3))
                socket.send(DatagramPacket(data, length, address, port))
            }
            BypassStrategy.UDP_FAKE_DTLS -> {
                val dtls = FakePacketHelper.buildDtlsClientHello()
                socket.send(DatagramPacket(dtls, dtls.size, address, port))
                delay(rnd.nextLong(2, 5))
                socket.send(DatagramPacket(data, length, address, port))
            }
            BypassStrategy.UDP_FAKE_SESSION, BypassStrategy.UDP_FAKE_TRAFFIC -> {
                val noise = FakePacketHelper.buildUdpNoise(rnd.nextInt(20, 60))
                socket.send(DatagramPacket(noise, noise.size, address, port))
                delay(rnd.nextLong(1, 3))
                socket.send(DatagramPacket(data, length, address, port))
            }
            BypassStrategy.UDP_NOISE_PAD, BypassStrategy.UDP_PADDING_CHAOS, BypassStrategy.UDP_QUIC_PAD, BypassStrategy.UDP_QUIC_JITTER_PAD -> {
                val padded = data.copyOf(length + rnd.nextInt(16, 64))
                val noise = ByteArray(padded.size - length)
                rnd.nextBytes(noise)
                System.arraycopy(noise, 0, padded, length, noise.size)
                socket.send(DatagramPacket(padded, padded.size, address, port))
            }
            BypassStrategy.QUIC_INITIAL_FAKE, BypassStrategy.QUIC_VERSION_SKEW -> {
                val quic = FakePacketHelper.buildQuicInitial(rnd.nextInt(100, 200))
                socket.send(DatagramPacket(quic, quic.size, address, port))
                delay(rnd.nextLong(2, 6))
                socket.send(DatagramPacket(data, length, address, port))
            }
            BypassStrategy.UDP_WIREGUARD_FAKE, BypassStrategy.UDP_IKE_FAKE, BypassStrategy.UDP_DHCP_FAKE, 
            BypassStrategy.UDP_TELEGRAM_FAKE, BypassStrategy.UDP_DISCORD_FAKE -> {
                val protocol = strategy.name.substringAfter("UDP_").substringBefore("_FAKE")
                val fake = FakePacketHelper.buildUdpProtocolFake(protocol)
                socket.send(DatagramPacket(fake, fake.size, address, port))
                delay(rnd.nextLong(2, 5))
                socket.send(DatagramPacket(data, length, address, port))
            }
            BypassStrategy.PROTOCOL_CONFUSION_QUIC, BypassStrategy.PROTOCOL_CONFUSION_DTLS -> {
                val proto = strategy.name.substringAfter("PROTOCOL_CONFUSION_")
                val fake = FakePacketHelper.buildProtocolConfusion(proto)
                socket.send(DatagramPacket(fake, fake.size, address, port))
                delay(rnd.nextLong(2, 5))
                socket.send(DatagramPacket(data, length, address, port))
            }
            BypassStrategy.UDP_HIGH_VOL_PACING -> {
                socket.send(DatagramPacket(data, length, address, port))
                delay(rnd.nextLong(1, 2))
                socket.send(DatagramPacket(data, length, address, port))
            }
            BypassStrategy.UDP_ZERO_LEN_SKEW -> {
                socket.send(DatagramPacket(ByteArray(0), 0, address, port))
                delay(rnd.nextLong(1, 3))
                socket.send(DatagramPacket(data, length, address, port))
            }
            BypassStrategy.UDP_NOISE_CHAOS, BypassStrategy.UDP_BURST_CHAOS -> {
                repeat(rnd.nextInt(2, 5)) {
                    val n = FakePacketHelper.buildUdpNoise(rnd.nextInt(10, 40))
                    socket.send(DatagramPacket(n, n.size, address, port))
                    delay(rnd.nextLong(1, 5))
                }
                socket.send(DatagramPacket(data, length, address, port))
            }
            BypassStrategy.UDP_QUIC_SKEW, BypassStrategy.UDP_QUIC_SMART_SHADOW, BypassStrategy.QUIC_HANDSHAKE_SKEW -> {
                if (length > 100) {
                    val part = length / 2
                    socket.send(DatagramPacket(data, part, address, port))
                    delay(rnd.nextLong(2, 6))
                    socket.send(DatagramPacket(data, length, address, port))
                } else {
                    socket.send(DatagramPacket(data, length, address, port))
                }
            }
            BypassStrategy.UDP_DATA_FRAG, BypassStrategy.UDP_FRAGMENTATION, BypassStrategy.UDP_FRAGMENT_SKEW, BypassStrategy.QUIC_INITIAL_FRAGMENT, BypassStrategy.QUIC_INITIAL_FRAGMENTATION, BypassStrategy.QUIC_FORCE_FRAG -> {
                val part = length / 2
                if (length > 20) {
                    socket.send(DatagramPacket(data, part, address, port))
                    delay(rnd.nextLong(5, 15))
                    socket.send(DatagramPacket(data.copyOfRange(part, length), length - part, address, port))
                } else {
                    socket.send(DatagramPacket(data, length, address, port))
                }
            }
            BypassStrategy.UDP_IP_FRAG, BypassStrategy.UDP_IPv6_FRAG -> {
                socket.send(DatagramPacket(data, length, address, port))
            }
            BypassStrategy.QUIC_MTU_PROBE, BypassStrategy.QUIC_INITIAL_PADDING_EXTREME -> {
                val padded = data.copyOf(1200.coerceAtLeast(length))
                if (padded.size > length) {
                    val noise = ByteArray(padded.size - length)
                    rnd.nextBytes(noise)
                    System.arraycopy(noise, 0, padded, length, noise.size)
                }
                socket.send(DatagramPacket(padded, padded.size, address, port))
            }
            BypassStrategy.UDP_REORDER, BypassStrategy.UDP_SKEW_ADVANCED, BypassStrategy.UDP_SKEW_REVERSE -> {
                if (length > 20) {
                    val part = length / 2
                    socket.send(DatagramPacket(data.copyOfRange(part, length), length - part, address, port))
                    delay(rnd.nextLong(5, 15))
                    socket.send(DatagramPacket(data, part, address, port))
                } else {
                    socket.send(DatagramPacket(data, length, address, port))
                }
            }
            BypassStrategy.UDP_HEARTBEAT, BypassStrategy.UDP_STUTTER -> {
                socket.send(DatagramPacket(data, length, address, port))
                delay(rnd.nextLong(200, 500))
                socket.send(DatagramPacket(ByteArray(1) { 0x00 }, 1, address, port))
            }
            BypassStrategy.UDP_REPLICATION -> {
                repeat(2) {
                    socket.send(DatagramPacket(data, length, address, port))
                    delay(rnd.nextLong(1, 3))
                }
            }
            BypassStrategy.UDP_FAKE_PACKET -> {
                val fake = FakePacketHelper.buildUdpNoise(length)
                socket.send(DatagramPacket(fake, fake.size, address, port))
                delay(rnd.nextLong(1, 4))
                socket.send(DatagramPacket(data, length, address, port))
            }
            else -> {
                socket.send(DatagramPacket(data, length, address, port))
            }
        }
    }
}
