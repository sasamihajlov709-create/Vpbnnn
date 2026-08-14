package com.aistudio.pinkproxy.fresh

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ThreadLocalRandom
import kotlinx.coroutines.delay

object UdpStrategyHandler : StrategyExecutor {
    override val executorType: StrategyExecutionRegistry.ExecutorType = StrategyExecutionRegistry.ExecutorType.UDP_HANDLER
    override val supportedTransports: Set<TransportType> = setOf(TransportType.UDP, TransportType.DNS)

    override fun supportsStrategy(strategy: BypassStrategy): Boolean {
        return StrategyExecutionRegistry.getExecutorType(strategy) == executorType
    }

    override suspend fun executeUdp(context: UdpExecutionContext) {
        handleUdpStrategies(
            socket = context.socket,
            address = context.address,
            port = context.port,
            data = context.data,
            length = context.length,
            rnd = context.random,
            host = context.host,
            strategy = context.strategy
        )
    }

    suspend fun handleUdpStrategies(socket: DatagramSocket, address: InetAddress, port: Int, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy) {
        if (strategy == BypassStrategy.DIRECT || UdpTransportHandler.isStunPacket(data.copyOf(length))) {
            socket.send(DatagramPacket(data, length, address, port))
            return
        }

        when (strategy) {
            BypassStrategy.UDP_STUN_FAKE -> {
                val stun = FakePacketHelper.buildStunBindingRequest()
                writeUdpWithFake(socket, address, port, stun, DatagramPacket(data, length, address, port), rnd.nextLong(1, 4))
            }
            BypassStrategy.UDP_FAKE_DTLS, BypassStrategy.PROTOCOL_CONFUSION_DTLS -> {
                val dtls = FakePacketHelper.buildDtlsClientHello()
                writeUdpWithFake(socket, address, port, dtls, DatagramPacket(data, length, address, port), rnd.nextLong(2, 5))
            }
            BypassStrategy.UDP_FAKE_SESSION, BypassStrategy.UDP_FAKE_TRAFFIC -> {
                val noise = FakePacketHelper.buildUdpNoise(rnd.nextInt(20, 60))
                writeUdpWithFake(socket, address, port, noise, DatagramPacket(data, length, address, port), rnd.nextLong(1, 3))
            }
            BypassStrategy.PROTOCOL_CONFUSION_QUIC, BypassStrategy.QUIC_INITIAL_FAKE, BypassStrategy.QUIC_VERSION_SKEW -> {
                val fakeVersion = if (strategy == BypassStrategy.QUIC_VERSION_SKEW) 0xff00001d.toInt() else 0x00000001
                val quic = GenericPacketBuilder.buildQuicInitial(version = fakeVersion, targetPacketSize = rnd.nextInt(1200, 1350))
                writeUdpWithFake(socket, address, port, quic, DatagramPacket(data, length, address, port), rnd.nextLong(2, 6))
            }
            BypassStrategy.UDP_WIREGUARD_FAKE, BypassStrategy.UDP_IKE_FAKE, BypassStrategy.UDP_DHCP_FAKE, 
            BypassStrategy.UDP_TELEGRAM_FAKE, BypassStrategy.UDP_DISCORD_FAKE -> {
                val protocol = strategy.name.substringAfter("UDP_").substringBefore("_FAKE")
                val fake = FakePacketHelper.buildUdpProtocolFake(protocol)
                writeUdpWithFake(socket, address, port, fake, DatagramPacket(data, length, address, port), rnd.nextLong(2, 5))
            }
            BypassStrategy.UDP_NOISE_PAD, BypassStrategy.UDP_QUIC_PAD, BypassStrategy.UDP_QUIC_JITTER_PAD -> {
                val padded = data.copyOf(length + rnd.nextInt(16, 64))
                val noise = ByteArray(padded.size - length)
                rnd.nextBytes(noise)
                System.arraycopy(noise, 0, padded, length, noise.size)
                socket.send(DatagramPacket(padded, padded.size, address, port))
            }
            BypassStrategy.UDP_HIGH_VOL_PACING -> {
                socket.send(DatagramPacket(data, length, address, port))
                delay(rnd.nextLong(1, 2))
                socket.send(DatagramPacket(data, length, address, port))
            }
            BypassStrategy.UDP_ZERO_LEN_SKEW -> {
                val empty = DatagramPacket(ByteArray(0), 0, address, port)
                try { socket.send(empty) } catch (e: Throwable) { android.util.Log.v("UdpStrategy", "Zero-len packet failed: ${e.message}") }
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
                val split = if (TlsParser.isClientHello(data, length, 0)) {
                    (TlsParser.findSniOffset(data, length, 0) - 2).coerceIn(10, length - 10)
                } else {
                    length / 2
                }
                
                if (length > 20) {
                    val shouldReorder = rnd.nextInt(100) < 30
                    if (shouldReorder) {
                        socket.send(DatagramPacket(data.copyOfRange(split, length), length - split, address, port))
                        delay(rnd.nextLong(1, 5))
                        socket.send(DatagramPacket(data, split, address, port))
                    } else {
                        socket.send(DatagramPacket(data, split, address, port))
                        delay(rnd.nextLong(1, 4))
                        socket.send(DatagramPacket(data.copyOfRange(split, length), length - split, address, port))
                    }
                } else {
                    socket.send(DatagramPacket(data, length, address, port))
                }
            }
            BypassStrategy.UDP_STUTTER -> {
                val chunks = rnd.nextInt(2, 5)
                var pos = 0
                for (i in 0 until chunks) {
                    val sz = if (i == chunks - 1) length - pos else (length / chunks)
                    if (sz > 0) {
                        socket.send(DatagramPacket(data, pos, sz, address, port))
                        pos += sz
                        delay(rnd.nextLong(2, 12))
                    }
                }
            }
            BypassStrategy.UDP_PADDING_CHAOS -> {
                val mtu = 1400 // Safe default MTU
                val targetSize = rnd.nextInt(mtu - 200, mtu - 40).coerceAtMost(1300)
                if (length < targetSize) {
                    val padded = ByteArray(targetSize)
                    System.arraycopy(data, 0, padded, 0, length)
                    val noise = ByteArray(targetSize - length)
                    rnd.nextBytes(noise)
                    System.arraycopy(noise, 0, padded, length, noise.size)
                    socket.send(DatagramPacket(padded, targetSize, address, port))
                } else {
                    socket.send(DatagramPacket(data, length, address, port))
                }
            }
            BypassStrategy.UDP_IP_FRAG, BypassStrategy.UDP_IPv6_FRAG -> {
                // Application-level fragmentation simulating MTU-split IP datagrams
                if (length > 28) {
                    val frag1 = (length / 2).coerceAtLeast(14)
                    socket.send(DatagramPacket(data, 0, frag1, address, port))
                    delay(rnd.nextLong(1, 3))
                    socket.send(DatagramPacket(data, frag1, length - frag1, address, port))
                } else {
                    socket.send(DatagramPacket(data, length, address, port))
                }
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
            BypassStrategy.UDP_HEARTBEAT -> {
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
                writeUdpWithFake(socket, address, port, fake, DatagramPacket(data, length, address, port), rnd.nextLong(1, 4))
            }
            BypassStrategy.QUIC_RST_SKEW -> {
                val fakeRst = ByteArray(20) { 0x00 }
                writeUdpWithFake(socket, address, port, fakeRst, DatagramPacket(data, length, address, port), rnd.nextLong(1, 3))
            }
            BypassStrategy.UDP_GHOST_SKEW -> {
                val ghost = FakePacketHelper.buildUdpNoise(rnd.nextInt(16, 48))
                writeUdpWithFake(socket, address, port, ghost, DatagramPacket(data, length, address, port), rnd.nextLong(1, 2))
            }
            BypassStrategy.UDP_IP_ID_MANGLE -> {
                // Prepend minimal 1-byte 0-TTL ping before packet to induce IP ID counter mismatch on middlebox state
                val ghost = ByteArray(4)
                rnd.nextBytes(ghost)
                val fakePkt = DatagramPacket(ghost, ghost.size, address, port)
                val isIpv6 = address is java.net.Inet6Address
                TtlHelper.setUdpTtl(socket, 1, isIpv6)
                try { socket.send(fakePkt) } catch (_: Throwable) {}
                TtlHelper.setUdpTtl(socket, BypassConfig.currentTtl, isIpv6)
                socket.send(DatagramPacket(data, length, address, port))
            }
            BypassStrategy.UDP_OVERLAP_SKEW -> {
                if (length > 30) {
                    val overlap = 10
                    val part1 = length / 2 + overlap
                    socket.send(DatagramPacket(data, part1, address, port))
                    delay(rnd.nextLong(1, 4))
                    val part2 = length - (length / 2)
                    socket.send(DatagramPacket(data, length / 2, part2, address, port))
                } else {
                    socket.send(DatagramPacket(data, length, address, port))
                }
            }
            BypassStrategy.UDP_COMBINED_HYBRID, BypassStrategy.UDP_COMBINED_NUCLEAR, BypassStrategy.UDP_QUIC_CHAOS, BypassStrategy.UDP_RACING -> {
                val noise = FakePacketHelper.buildUdpNoise(rnd.nextInt(20, 60))
                writeUdpWithFake(socket, address, port, noise, DatagramPacket(data, length, address, port), rnd.nextLong(1, 3))
                if (length > 40) {
                    val part = length / 2
                    delay(rnd.nextLong(1, 2))
                    socket.send(DatagramPacket(data, part, address, port))
                    delay(rnd.nextLong(1, 3))
                    socket.send(DatagramPacket(data, part, length - part, address, port))
                }
            }
            BypassStrategy.ADAPTIVE_CHUNK, BypassStrategy.BYEBYEDPI_SIM, BypassStrategy.CHAOS -> {
                if (length > 20) {
                    val part = length / 2
                    socket.send(DatagramPacket(data, part, address, port))
                    delay(rnd.nextLong(1, 4))
                    socket.send(DatagramPacket(data, part, length - part, address, port))
                } else {
                    socket.send(DatagramPacket(data, length, address, port))
                }
            }
            else -> {
                socket.send(DatagramPacket(data, length, address, port))
            }
        }
    }

    private suspend fun writeUdpWithFake(
        socket: DatagramSocket,
        targetAddr: InetAddress,
        targetPort: Int,
        fakeData: ByteArray,
        realPacket: DatagramPacket,
        delayMs: Long
    ) {
        val ghost = DatagramPacket(fakeData, fakeData.size, targetAddr, targetPort)
        val discoveredTtl = AutoTtlProber.getDiscoveredTtl(targetAddr.hostAddress ?: "") ?: 3
        val isIpv6 = targetAddr is java.net.Inet6Address
        TtlHelper.setUdpTtl(socket, discoveredTtl, isIpv6)
        try { socket.send(ghost) } catch (e: Throwable) { android.util.Log.v("UdpStrategy", "Fake UDP send failed: ${e.message}") }
        TtlHelper.setUdpTtl(socket, BypassConfig.currentTtl, isIpv6)
        delay(delayMs)
        socket.send(realPacket)
    }
}
