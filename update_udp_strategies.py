with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    code = f.read()

target = """            BypassStrategy.UDP_TELEGRAM_FAKE -> {
                val fake = FakePacketHelper.buildUdpNoise(48)
                writeUdpWithFake(socket, targetAddr, targetPort, fake, packet, config)
            }"""

replacement = """            BypassStrategy.UDP_TELEGRAM_FAKE -> {
                val fake = FakePacketHelper.buildUdpNoise(48)
                writeUdpWithFake(socket, targetAddr, targetPort, fake, packet, config)
            }
            BypassStrategy.UDP_DISCORD_FAKE -> {
                val fake = FakePacketHelper.buildUdpNoise(64)
                writeUdpWithFake(socket, targetAddr, targetPort, fake, packet, config)
            }
            BypassStrategy.UDP_IKE_FAKE -> {
                val fake = FakePacketHelper.getCachedIke()
                writeUdpWithFake(socket, targetAddr, targetPort, fake, packet, config)
            }
            BypassStrategy.UDP_DHCP_FAKE -> {
                val fake = FakePacketHelper.getCachedDhcp()
                writeUdpWithFake(socket, targetAddr, targetPort, fake, packet, config)
            }
            BypassStrategy.UDP_DNS_REORDER_HYBRID -> {
                if (targetPort == 53) {
                    val fakeDns = FakePacketHelper.buildDnsFakeQuery("google.com")
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
            }"""

if target in code:
    code = code.replace(target, replacement, 1)
    with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "w") as f:
        f.write(code)
    print("Successfully added missing UDP strategies")
else:
    print("Target block not found!")
