import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/UdpStrategyHandler.kt", "r") as f:
    content = f.read()

replacement = """
            BypassStrategy.UDP_DATA_FRAG, BypassStrategy.UDP_FRAGMENTATION, BypassStrategy.UDP_FRAGMENT_SKEW, BypassStrategy.QUIC_INITIAL_FRAGMENT, BypassStrategy.QUIC_INITIAL_FRAGMENTATION, BypassStrategy.QUIC_FORCE_FRAG -> {
                // Application-level fragmentation of UDP datagrams breaks the protocol (e.g., QUIC).
                // Instead, we bypass DPI by sending a fake QUIC Initial or UDP noise packet to saturate/confuse the DPI state machine,
                // followed by the real, unmodified datagram.
                val fakeQuic = FakePacketHelper.buildQuicInitial()
                val shouldReorder = rnd.nextInt(100) < 30
                
                if (shouldReorder) {
                    writeUdpWithFake(socket, address, port, fakeQuic, DatagramPacket(data, length, address, port), rnd.nextLong(1, 5))
                } else {
                    writeUdpWithFake(socket, address, port, FakePacketHelper.getSmallNoise(rnd.nextInt(16, 64)), DatagramPacket(data, length, address, port), rnd.nextLong(1, 4))
                }
            }
            BypassStrategy.UDP_STUTTER -> {
                // Stuttering by splitting UDP payload breaks it. We stutter by sending multiple small noise packets before the real one.
                val chunks = rnd.nextInt(2, 5)
                for (i in 0 until chunks) {
                    val noise = FakePacketHelper.getSmallNoise(rnd.nextInt(8, 32))
                    socket.send(DatagramPacket(noise, noise.size, address, port))
                    delay(rnd.nextLong(1, 4))
                }
                socket.send(DatagramPacket(data, length, address, port))
            }
"""

content = re.sub(
    r'            BypassStrategy\.UDP_DATA_FRAG,.*?BypassStrategy\.QUIC_FORCE_FRAG -> \{.*?BypassStrategy\.UDP_STUTTER -> \{.*?\}\n',
    replacement.lstrip('\n'),
    content,
    flags=re.DOTALL
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/UdpStrategyHandler.kt", "w") as f:
    f.write(content)

