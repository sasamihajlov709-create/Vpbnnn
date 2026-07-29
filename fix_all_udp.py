import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    code = f.read()

# Replace UDP_SKEW_ADVANCED
code = re.sub(r"""BypassStrategy\.UDP_SKEW_ADVANCED -> \{[\s\S]*?TtlHelper\.setUdpTtl\(socket, 64, isIpv6\)[\s\S]*?if \(length > 20\) \{[\s\S]*?socket\.send\(packet\)[\s\S]*?\}[\s\S]*?\}""", 
    """BypassStrategy.UDP_SKEW_ADVANCED -> {
                try {
                    val fake = FakePacketHelper.buildUdpNoise(rnd.nextInt(10, 30))
                    val isIpv6 = targetAddr is java.net.Inet6Address
                    TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5), isIpv6)
                    socket.send(DatagramPacket(fake, fake.size, targetAddr, targetPort))
                    delay(rnd.nextLong(1, 3))
                    
                    // 2. Real data
                    TtlHelper.setUdpTtl(socket, 64, isIpv6)
                    socket.send(packet)
                } catch(e: Throwable) { socket.send(packet) }
            }""", code)

# Replace QUIC_INITIAL_FRAGMENT
code = re.sub(r"""BypassStrategy\.QUIC_INITIAL_FRAGMENT -> \{[\s\S]*?if \(length > 200.*?\{[\s\S]*?\} else \{[\s\S]*?socket\.send\(packet\)[\s\S]*?\}[\s\S]*?\}""",
    """BypassStrategy.QUIC_INITIAL_FRAGMENT -> {
                if (length > 200 && (data[offset].toInt() and 0xC0) == 0xC0) {
                    val noise = FakePacketHelper.buildUdpNoise(128)
                    try { socket.send(DatagramPacket(noise, noise.size, targetAddr, targetPort)) } catch(e: Throwable) {}
                    delay(rnd.nextLong(1, 4))
                }
                socket.send(packet)
            }""", code)

# Replace QUIC_INITIAL_FRAGMENTATION
code = re.sub(r"""BypassStrategy\.QUIC_INITIAL_FRAGMENTATION -> \{[\s\S]*?if \(length > 400.*?\{[\s\S]*?\} else \{[\s\S]*?socket\.send\(packet\)[\s\S]*?\}[\s\S]*?\}""",
    """BypassStrategy.QUIC_INITIAL_FRAGMENTATION -> {
                if (length > 400 && (data[offset].toInt() and 0xC0) == 0xC0) {
                    val noise = FakePacketHelper.buildUdpNoise(256)
                    try { socket.send(DatagramPacket(noise, noise.size, targetAddr, targetPort)) } catch(e: Throwable) {}
                    delay(rnd.nextLong(1, 3))
                }
                socket.send(packet)
            }""", code)

# Replace UDP_SKEW_REVERSE
code = re.sub(r"""BypassStrategy\.UDP_SKEW_REVERSE -> \{[\s\S]*?if \(length > 40\) \{[\s\S]*?\} else \{[\s\S]*?socket\.send\(packet\)[\s\S]*?\}[\s\S]*?\}""",
    """BypassStrategy.UDP_SKEW_REVERSE -> {
                if (length > 40) {
                    val noise = FakePacketHelper.buildUdpNoise(32)
                    try { socket.send(DatagramPacket(noise, noise.size, targetAddr, targetPort)) } catch(e: Throwable) {}
                    delay(rnd.nextLong(1, 4))
                }
                socket.send(packet)
            }""", code)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "w") as f:
    f.write(code)
