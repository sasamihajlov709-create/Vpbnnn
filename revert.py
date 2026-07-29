import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    code = f.read()

# Replace the specific block of our bad insertion
bad_code = """BypassStrategy.UDP_DNS_REORDER_HYBRID -> {
                // If it's DNS (port 53), send a fake query first
                if (targetPort == 53) {
                    val fakeDns = FakePacketHelper.buildDnsQuery("google.com")
                    try {
                        TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5), isIpv6)
                        socket.send(DatagramPacket(fakeDns, fakeDns.size, targetAddr, targetPort))
                    } catch (e: Throwable) {}
                    delay(rnd.nextLong(2, 6))
                    TtlHelper.setUdpTtl(socket, 64, isIpv6)
                    socket.send(packet)
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.UDP_REORDER -> {
                if (length > 100) {
                    val split = length / 2
                    val p1 = data.copyOfRange(offset, offset + split)
                    val p2 = data.copyOfRange(offset + split, offset + length)
                    try {
                        socket.send(DatagramPacket(p2, p2.size, targetAddr, targetPort))
                        delay(rnd.nextLong(1, 3))
                        socket.send(DatagramPacket(p1, p1.size, targetAddr, targetPort))
                    } catch(e: Throwable) { socket.send(packet) }
                } else {
                    socket.send(packet)
                }
            }
            else -> {"""

code = code.replace(bad_code, "else -> {", 1)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "w") as f:
    f.write(code)
