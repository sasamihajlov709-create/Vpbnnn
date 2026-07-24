cat app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt | awk '
BEGIN { p = 1 }
/private suspend fun sendUdpPacket/ { p = 0 }
p { print }
' > temp.kt

cat << 'INNER_EOF' >> temp.kt
    private suspend fun sendUdpPacket(socket: java.net.DatagramSocket, payload: ByteArray, targetInet: java.net.InetAddress, targetPort: Int, targetHost: String = "") {
        val outPacket = java.net.DatagramPacket(payload, payload.size, targetInet, targetPort)
        val strategy = BypassConfig.getBestStrategyForHost(if (targetHost.isNotEmpty()) targetHost else targetInet.hostAddress)
        
        val isQuic = targetPort == 443 && payload.isNotEmpty() && (payload[0].toInt() and 0xC0) == 0xC0
        
        if (BypassConfig.blockQuic && isQuic) {
            return
        }

        if (strategy == BypassStrategy.DIRECT) {
            socket.send(outPacket)
            return
        }

        if (isQuic) {
            when (strategy) {
                BypassStrategy.QUIC_INITIAL_FAKE -> {
                    val fakeQuic = FakePacketHelper.buildQuicInitial()
                    val fakeQuicPacket = java.net.DatagramPacket(fakeQuic, fakeQuic.size, targetInet, targetPort)
                    TtlHelper.setUdpTtl(socket, 5)
                    socket.send(fakeQuicPacket)
                    delay(3)
                    TtlHelper.setUdpTtl(socket, 64)
                    socket.send(outPacket)
                }
                BypassStrategy.QUIC_RST_SKEW -> {
                    val rstPayload = FakePacketHelper.buildFakeUdpPacket(20) // Simulated QUIC Reset
                    val rstPacket = java.net.DatagramPacket(rstPayload, rstPayload.size, targetInet, targetPort)
                    TtlHelper.setUdpTtl(socket, 3)
                    socket.send(rstPacket)
                    delay(2)
                    TtlHelper.setUdpTtl(socket, 64)
                    socket.send(outPacket)
                }
                else -> {
                    // Default QUIC obfuscation
                    val fakeQuic = FakePacketHelper.buildQuicInitial()
                    val fakeQuicPacket = java.net.DatagramPacket(fakeQuic, fakeQuic.size, targetInet, targetPort)
                    TtlHelper.setUdpTtl(socket, 5)
                    socket.send(fakeQuicPacket)
                    delay(3)
                    TtlHelper.setUdpTtl(socket, 64)
                    socket.send(outPacket)
                }
            }
        } else if (targetPort == 53) {
            when (strategy) {
                BypassStrategy.DNS_NOISE -> {
                    val noise = FakePacketHelper.buildFakeUdpPacket(50)
                    val noisePacket = java.net.DatagramPacket(noise, noise.size, targetInet, targetPort)
                    TtlHelper.setUdpTtl(socket, 4)
                    socket.send(noisePacket)
                    delay(2)
                    TtlHelper.setUdpTtl(socket, 64)
                    socket.send(outPacket)
                }
                else -> {
                    // Default DNS Obfuscation
                    val noise = FakePacketHelper.buildQuicInitial() // Confuse DPI with QUIC on port 53
                    val noisePacket = java.net.DatagramPacket(noise, noise.size, targetInet, targetPort)
                    TtlHelper.setUdpTtl(socket, 5)
                    socket.send(noisePacket)
                    delay(3)
                    TtlHelper.setUdpTtl(socket, 64)
                    socket.send(outPacket)
                }
            }
        } else {
            // General UDP Obfuscation
            val noise = FakePacketHelper.buildFakeUdpPacket(java.util.concurrent.ThreadLocalRandom.current().nextInt(30, 150))
            val noisePacket = java.net.DatagramPacket(noise, noise.size, targetInet, targetPort)
            TtlHelper.setUdpTtl(socket, 5)
            socket.send(noisePacket)
            delay(3)
            TtlHelper.setUdpTtl(socket, 64)
            socket.send(outPacket)
        }
    }
}
INNER_EOF
mv temp.kt app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt
