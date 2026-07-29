import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    code = f.read()

# Replace ZAPRET_EXTREME UDP payload splitting
code = re.sub(r"""// Real data fragmented if possible \(QUIC initial\)[\s\S]*?TtlHelper\.setUdpTtl\(socket, 64, isIpv6\)[\s\S]*?if \(length > 100.*?\{[\s\S]*?\} else \{[\s\S]*?socket\.send\(packet\)[\s\S]*?\}""",
    """// Real data
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                if (length > 100 && (data[offset].toInt() and 0xC0) == 0xC0) {
                    val padding = FakePacketHelper.buildUdpNoise(rnd.nextInt(64, 128))
                    val combined = data.copyOfRange(offset, offset + length) + padding
                    socket.send(DatagramPacket(combined, combined.size, targetAddr, targetPort))
                } else {
                    socket.send(packet)
                }""", code)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "w") as f:
    f.write(code)
