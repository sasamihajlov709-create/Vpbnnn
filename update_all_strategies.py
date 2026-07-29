with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    code = f.read()

# 1. Update UDP when block
udp_target = """            BypassStrategy.UDP_DNS_REORDER_HYBRID -> {
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

udp_additions = """            BypassStrategy.UDP_DNS_REORDER_HYBRID -> {
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
            }
            BypassStrategy.QUIC_RST_SKEW -> {
                val resetPacket = byteArrayOf(0x00, 0x00, 0x00, 0x00) + FakePacketHelper.buildUdpNoise(16)
                try {
                    TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5), isIpv6)
                    socket.send(DatagramPacket(resetPacket, resetPacket.size, targetAddr, targetPort))
                } catch (e: Throwable) {}
                delay(config.delay1)
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                socket.send(packet)
            }
            BypassStrategy.UDP_HEARTBEAT -> {
                val heartbeat = byteArrayOf(0x01, 0x00, 0x00, 0x00)
                try { socket.send(DatagramPacket(heartbeat, heartbeat.size, targetAddr, targetPort)) } catch (e: Throwable) {}
                delay(2)
                socket.send(packet)
            }
            BypassStrategy.UDP_HIGH_VOL_PACING -> {
                val count = rnd.nextInt(2, 5)
                for (i in 0 until count) {
                    val noise = FakePacketHelper.buildUdpNoise(rnd.nextInt(8, 24))
                    try { socket.send(DatagramPacket(noise, noise.size, targetAddr, targetPort)) } catch (e: Throwable) {}
                    delay(rnd.nextLong(1, 3))
                }
                socket.send(packet)
            }
            BypassStrategy.QUIC_INITIAL_FAKE -> {
                val fakeQuic = FakePacketHelper.buildQuicInitialFake()
                try {
                    TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5), isIpv6)
                    socket.send(DatagramPacket(fakeQuic, fakeQuic.size, targetAddr, targetPort))
                } catch (e: Throwable) {}
                delay(config.delay1)
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                socket.send(packet)
            }
            BypassStrategy.DNS_NOISE -> {
                val fakeDns = FakePacketHelper.buildDnsFakeQuery("cloudflare.com")
                try { socket.send(DatagramPacket(fakeDns, fakeDns.size, targetAddr, targetPort)) } catch (e: Throwable) {}
                delay(2)
                socket.send(packet)
            }
            BypassStrategy.DNS_OVER_TCP_FORCE -> {
                socket.send(packet)
            }"""

if udp_target in code:
    code = code.replace(udp_target, udp_additions, 1)
    print("UDP additions applied successfully")
else:
    print("UDP target not found!")

# 2. Update TCP when block
tcp_target = """            BypassStrategy.TLS_SNI_REVERSE -> {
                // Reverse SNI in handshake fake
                val reversedSni = host.reversed()
                val fakeHello = FakePacketHelper.buildRealisticTlsHello(reversedSni)
                TtlHelper.setTtl(socket, config.fakeTtl)
                output.write(fakeHello); output.flush()
                delay(config.delay1)
                TtlHelper.setTtl(socket, 64)
                output.write(finalData, 0, finalLen); output.flush()
            }"""

tcp_additions = """            BypassStrategy.TLS_SNI_REVERSE -> {
                val reversedSni = host.reversed()
                val fakeHello = FakePacketHelper.buildRealisticTlsHello(reversedSni)
                TtlHelper.setTtl(socket, config.fakeTtl)
                output.write(fakeHello); output.flush()
                delay(config.delay1)
                TtlHelper.setTtl(socket, 64)
                output.write(finalData, 0, finalLen); output.flush()
            }
            BypassStrategy.TCP_MSS_CLAMP -> {
                try { TtlHelper.setMss(socket, rnd.nextInt(256, 512)) } catch (e: Throwable) {}
                val split = (finalLen / 2).coerceIn(1, finalLen - 1)
                output.write(finalData, 0, split); output.flush()
                delay(config.delay1)
                output.write(finalData, split, finalLen - split); output.flush()
                try { TtlHelper.setMss(socket, 1400) } catch (e: Throwable) {}
            }
            BypassStrategy.TCP_SMALL_CHUNKS -> {
                var pos = 0
                val chunkSize = rnd.nextInt(2, 8)
                while (pos < finalLen) {
                    val len = minOf(chunkSize, finalLen - pos)
                    output.write(finalData, pos, len); output.flush()
                    pos += len
                    if (pos < finalLen) delay(rnd.nextLong(1, 4))
                }
            }
            BypassStrategy.TCP_TIMESTAMP_MANGLE -> {
                val p1 = finalData.copyOfRange(0, 1)
                val p2 = finalData.copyOfRange(1, finalLen)
                output.write(p1); output.flush()
                try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                delay(config.delay1)
                output.write(p2); output.flush()
            }
            BypassStrategy.TCP_WINDOW_SCAN -> {
                try { socket.receiveBufferSize = 512 } catch (e: Throwable) {}
                val split = 1
                output.write(finalData, 0, split); output.flush()
                delay(config.delay1)
                try { socket.receiveBufferSize = 65536 } catch (e: Throwable) {}
                output.write(finalData, split, finalLen - split); output.flush()
            }
            BypassStrategy.TLS_DIRTY -> {
                val dirtyData = FakePacketHelper.addTlsGreaseExtensions(finalData, finalLen)
                val split = (dirtyData.size / 2).coerceIn(1, dirtyData.size - 1)
                output.write(dirtyData, 0, split); output.flush()
                delay(config.delay1)
                output.write(dirtyData, split, dirtyData.size - split); output.flush()
            }
            BypassStrategy.TLS_PADDING_RAND -> {
                val padLen = rnd.nextInt(64, 512)
                val padded = FakePacketHelper.injectTlsPadding(finalData, finalLen, padLen)
                val split = (padded.size / 2).coerceIn(1, padded.size - 1)
                output.write(padded, 0, split); output.flush()
                delay(config.delay1)
                output.write(padded, split, padded.size - split); output.flush()
            }
            BypassStrategy.TLS_SNI_GREASE -> {
                val greased = FakePacketHelper.injectTlsGrease(finalData, finalLen)
                output.write(greased, 0, greased.size); output.flush()
            }
            BypassStrategy.WINDOW_SIZE_MANGLE -> {
                try { socket.receiveBufferSize = rnd.nextInt(256, 1024) } catch (e: Throwable) {}
                val split = (finalLen / 2).coerceIn(1, finalLen - 1)
                output.write(finalData, 0, split); output.flush()
                delay(config.delay1)
                try { socket.receiveBufferSize = 65536 } catch (e: Throwable) {}
                output.write(finalData, split, finalLen - split); output.flush()
            }"""

if tcp_target in code:
    code = code.replace(tcp_target, tcp_additions, 1)
    print("TCP additions applied successfully")
else:
    print("TCP target not found!")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "w") as f:
    f.write(code)

