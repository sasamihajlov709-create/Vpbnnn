package com.aistudio.pinkproxy.fresh

object FakePacketHelper {
    
    fun buildRealisticTlsHello(host: String) = TlsPacketBuilder.buildRealisticTlsHello(host)
    fun buildRealisticHttp2Header() = HttpPacketBuilder.buildRealisticHttp2Header()
    fun buildHttpChaosPacket() = HttpPacketBuilder.buildHttpChaosPacket()
    fun buildFakeHttpRequest(host: String) = HttpPacketBuilder.buildFakeHttpRequest(host)
    
    fun buildUdpNoise(size: Int) = NoiseGenerator.buildUdpNoise(size)
    fun getSmallNoise(size: Int) = NoiseGenerator.getSmallNoise(size)

    fun buildQuicInitial(scid: String? = null) = GenericPacketBuilder.buildQuicInitial(scid)
    fun buildDtlsClientHello() = GenericPacketBuilder.buildDtlsClientHello()
    fun buildUdpProtocolFake(type: String) = GenericPacketBuilder.buildUdpProtocolFake(type)
    fun buildStunBindingRequest() = GenericPacketBuilder.buildStunBindingRequest()
    fun buildWireguardFake() = GenericPacketBuilder.buildWireguardHandshake()
    fun buildIkeHandshake() = GenericPacketBuilder.buildIkeHandshake()
    fun buildDhcpRequest() = GenericPacketBuilder.buildDhcpRequest()
    fun buildSshHandshake() = GenericPacketBuilder.buildSshHandshake()
    fun buildTelegramFake() = GenericPacketBuilder.buildTelegramFake()
    fun buildDiscordFake() = GenericPacketBuilder.buildDiscordFake()

    fun mangleSessionId(data: ByteArray, length: Int) = TlsPacketBuilder.mangleSessionId(data, length)
    fun injectTlsPadding(data: ByteArray, length: Int, padLen: Int) = TlsPacketBuilder.injectTlsPadding(data, length, padLen)
    fun addTlsGreaseExtensions(data: ByteArray, length: Int) = TlsPacketBuilder.addTlsGreaseExtensions(data, length)
    fun shuffleTlsExtensions(data: ByteArray, length: Int) = TlsPacketBuilder.shuffleTlsExtensions(data, length)
    fun injectMultipleSni(data: ByteArray, length: Int, extraHost: String) = TlsPacketBuilder.injectMultipleSni(data, length, extraHost)
    fun buildChromeHello(host: String) = TlsPacketBuilder.buildChromeHello(host)
    fun buildFirefoxHello(host: String) = TlsPacketBuilder.buildFirefoxHello(host)
    fun buildTls13Hello(host: String) = TlsPacketBuilder.buildTls13Hello(host)

    fun mangleHttpMethod(data: ByteArray, length: Int) = EvasionPacketMangler.mangleHttpMethodCase(data, length)
    fun mangleHttpMethodCase(data: ByteArray, length: Int) = EvasionPacketMangler.mangleHttpMethodCase(data, length)
    fun randomizeHeaderCase(data: ByteArray, length: Int) = EvasionPacketMangler.randomizeHeaderCase(data, length)
    fun addSpaceToHttpMethod(data: ByteArray, length: Int) = EvasionPacketMangler.addSpaceToHttpMethod(data, length)
    fun addDotToHost(data: ByteArray, length: Int) = EvasionPacketMangler.addDotToHost(data, length)

    fun buildHandshakeCombo(noiseSize: Int = 64): ByteArray {
        val rnd = java.util.concurrent.ThreadLocalRandom.current()
        return when (rnd.nextInt(3)) {
            0 -> GenericPacketBuilder.buildSshHandshake() + "\r\n".toByteArray() + HttpPacketBuilder.buildFakeHttpRequest("google.com")
            1 -> TlsPacketBuilder.buildRealisticTlsHello("youtube.com") + NoiseGenerator.buildUdpNoise(noiseSize)
            else -> byteArrayOf(0, 0, 0, 1) + GenericPacketBuilder.buildSshHandshake() + NoiseGenerator.buildUdpNoise(noiseSize / 2)
        }
    }

    fun buildProtocolConfusion(type: String): ByteArray {
        return when(type.uppercase()) {
            "SSH" -> buildSshHandshake()
            "STUN" -> buildStunBindingRequest()
            "HTTP" -> buildFakeHttpRequest("google.com")
            "BITTORRENT" -> GenericPacketBuilder.buildBitTorrentHandshake()
            "QUIC" -> buildQuicInitial()
            "TELEGRAM" -> buildTelegramFake()
            "DISCORD" -> buildDiscordFake()
            else -> buildUdpNoise(32)
        }
    }
}
