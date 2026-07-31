package com.aistudio.pinkproxy.fresh

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.util.concurrent.ThreadLocalRandom
import java.nio.charset.StandardCharsets
import android.util.Base64

object FakePacketHelper {
    private var cachedQuicInitial = buildQuicInitial()
    private var cachedStun = buildStunBindingRequest()
    private var cachedDtls = buildFakeDtlsClientHello()
    private var cachedWg = buildWireGuardHandshake()
    private var cachedIke = buildIkeHandshake()
    private var cachedDhcp = buildDhcpRequest()
    
    private var cacheTime = System.currentTimeMillis()
    
    private fun checkCacheRefresh() {
        if (System.currentTimeMillis() - cacheTime > 30000) {
            cachedQuicInitial = buildQuicInitial()
            cachedStun = buildStunBindingRequest()
            cachedDtls = buildFakeDtlsClientHello()
            cachedWg = buildWireGuardHandshake()
            cachedIke = buildIkeHandshake()
            cachedDhcp = buildDhcpRequest()
            cacheTime = System.currentTimeMillis()
        }
    }
    
    fun getCachedQuicInitial() = run { checkCacheRefresh(); cachedQuicInitial }
    fun getCachedStun() = run { checkCacheRefresh(); cachedStun }
    fun getCachedDtls() = run { checkCacheRefresh(); cachedDtls }
    fun getCachedWg() = run { checkCacheRefresh(); cachedWg }
    fun getCachedIke() = run { checkCacheRefresh(); cachedIke }
    fun getCachedDhcp() = run { checkCacheRefresh(); cachedDhcp }

    fun buildExtension(type: Int, data: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)
        dos.writeShort(type)
        dos.writeShort(data.size)
        dos.write(data)
        return baos.toByteArray()
    }

    fun buildSniExtension(host: String): ByteArray {
        val bos = ByteArrayOutputStream()
        val dos = DataOutputStream(bos)
        val hostBytes = host.toByteArray(StandardCharsets.UTF_8)
        dos.writeShort(0x0000)
        dos.writeShort(hostBytes.size + 5)
        dos.writeShort(hostBytes.size + 3)
        dos.writeByte(0)
        dos.writeShort(hostBytes.size)
        dos.write(hostBytes)
        return bos.toByteArray()
    }

    fun injectExtension(data: ByteArray, length: Int, type: Int, extData: ByteArray): ByteArray {
        if (length < 44 || data[0] != 0x16.toByte()) return data.copyOf(length)
        try {
            val baos = ByteArrayOutputStream()
            val dos = DataOutputStream(baos)
            var pos = 5 + 4 + 2 + 32 
            if (length < pos + 1) return data.copyOf(length)
            val sidLen = data[pos].toInt() and 0xFF
            pos += 1 + sidLen
            if (length < pos + 2) return data.copyOf(length)
            val cipherLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
            pos += 2 + cipherLen
            if (length < pos + 1) return data.copyOf(length)
            val compLen = data[pos].toInt() and 0xFF
            pos += 1 + compLen
            if (pos >= length - 1) return data.copyOf(length)
            val oldExtLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos+1].toInt() and 0xFF)
            dos.write(data, 0, pos)
            dos.writeShort(oldExtLen + extData.size + 4)
            if (oldExtLen > 0) dos.write(data, pos + 2, oldExtLen)
            dos.writeShort(type); dos.writeShort(extData.size); dos.write(extData)
            val result = baos.toByteArray()
            val recLen = result.size - 5
            result[3] = ((recLen shr 8) and 0xFF).toByte(); result[4] = (recLen and 0xFF).toByte()
            val handLen = result.size - 9
            result[6] = ((handLen shr 16) and 0xFF).toByte(); result[7] = ((handLen shr 8) and 0xFF).toByte(); result[8] = (handLen and 0xFF).toByte()
            return result
        } catch (e: Exception) { return data.copyOf(length) }
    }

    fun buildWireguardFake(): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val baos = ByteArrayOutputStream(); val dos = DataOutputStream(baos)
        dos.writeByte(0x01); dos.write(byteArrayOf(0, 0, 0)); dos.writeInt(rnd.nextInt())
        dos.write(ByteArray(32).apply { rnd.nextBytes(this) })
        dos.write(ByteArray(48).apply { rnd.nextBytes(this) })
        dos.write(ByteArray(28).apply { rnd.nextBytes(this) })
        dos.write(ByteArray(16).apply { rnd.nextBytes(this) })
        dos.write(ByteArray(16).apply { rnd.nextBytes(this) })
        return baos.toByteArray()
    }

    fun buildHandshakeCombo(noiseSize: Int = 32): ByteArray {
        val baos = ByteArrayOutputStream()
        baos.write(buildSshHandshake())
        baos.write(buildUdpNoise(noiseSize))
        return baos.toByteArray()
    }

    fun injectGrease(data: ByteArray, length: Int): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val grease = ByteArray(rnd.nextInt(2, 8))
        rnd.nextBytes(grease)
        return injectExtension(data, length, 0x1a1a + rnd.nextInt(0, 10) * 0x1111, grease)
    }

    fun buildOpenVpnFake(): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val baos = ByteArrayOutputStream(); val dos = DataOutputStream(baos)
        dos.writeByte((0x07 shl 3) or 0x00)
        dos.write(ByteArray(8).apply { rnd.nextBytes(this) })
        dos.writeByte(0x00); dos.writeInt(rnd.nextInt()); dos.writeInt((System.currentTimeMillis() / 1000).toInt())
        return baos.toByteArray()
    }

    fun buildQuicInitialReal(dcid: ByteArray, scid: ByteArray, payload: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream(); val dos = DataOutputStream(baos)
        // Header: Initial (0xC0 | packet number length 3 = 0xC3), Version 1
        dos.writeByte(0xC3); dos.writeInt(0x00000001)
        dos.writeByte(dcid.size); dos.write(dcid)
        dos.writeByte(scid.size); dos.write(scid)
        dos.writeByte(0x00) // Token Length
        
        // Length field (Varint)
        val len = payload.size + 4 // + packet number
        if (len < 64) dos.writeByte(len)
        else { dos.writeByte(0x40 or (len shr 8)); dos.writeByte(len and 0xFF) }
        
        dos.writeInt(ThreadLocalRandom.current().nextInt()) // Packet Number
        dos.write(payload)
        return baos.toByteArray()
    }

    fun buildQuicInitialExtremePadding(): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val data = ByteArray(rnd.nextInt(1280, 1450)).apply { rnd.nextBytes(this) }
        data[0] = (0xC0 or (rnd.nextInt(4) shl 4) or rnd.nextInt(16)).toByte()
        data[1] = 0x00; data[2] = 0x00; data[3] = 0x00; data[4] = 0x01
        return data
    }

    fun mangleSessionId(data: ByteArray, length: Int): ByteArray {
        val copy = data.copyOfRange(0, length)
        try {
            val sidLenOffset = 5 + 1 + 3 + 2 + 32
            if (length > sidLenOffset + 32) {
                val sidLen = copy[sidLenOffset].toInt() and 0xFF
                if (sidLen > 0 && sidLen <= 32) {
                    val rnd = ThreadLocalRandom.current()
                    for (i in 0 until sidLen) copy[sidLenOffset + 1 + i] = rnd.nextInt(256).toByte()
                }
            }
        } catch (e: Throwable) {}
        return copy
    }

    fun buildUdpNoise(size: Int): ByteArray = ByteArray(size).apply { ThreadLocalRandom.current().nextBytes(this) }

    fun buildEchFakeRecord(host: String): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val baos = ByteArrayOutputStream(); val dos = DataOutputStream(baos)
        dos.writeByte(22); dos.writeShort(0x0303)
        val innerBaos = ByteArrayOutputStream(); val innerDos = DataOutputStream(innerBaos)
        innerDos.writeByte(1); innerDos.write(byteArrayOf(0, 0, 0)); innerDos.writeShort(0x0303)
        innerDos.write(ByteArray(32).apply { rnd.nextBytes(this) })
        innerDos.writeByte(0); innerDos.writeShort(2); innerDos.writeShort(0x1301)
        innerDos.writeByte(1); innerDos.writeByte(0)
        val extBaos = ByteArrayOutputStream(); val extDos = DataOutputStream(extBaos)
        extDos.write(buildSniExtension(listOf("google.com", "cloudflare.com").random()))
        extDos.writeShort(0xfe0d); val ech = buildUdpNoise(rnd.nextInt(128, 256))
        extDos.writeShort(ech.size); extDos.write(ech)
        val exts = extBaos.toByteArray(); innerDos.writeShort(exts.size); innerDos.write(exts)
        val inner = innerBaos.toByteArray()
        val ilen = inner.size - 4
        inner[1] = ((ilen shr 16) and 0xFF).toByte(); inner[2] = ((ilen shr 8) and 0xFF).toByte(); inner[3] = (ilen and 0xFF).toByte()
        dos.writeShort(inner.size); dos.write(inner)
        return baos.toByteArray()
    }

    fun buildFakeTcpRst(): ByteArray = byteArrayOf(0x52, 0x53, 0x54, 0x00, 0x00, 0x00) + buildUdpNoise(ThreadLocalRandom.current().nextInt(2, 10))
    fun buildFakeTcpKeepAlive(): ByteArray = byteArrayOf(0x00)

    fun buildFakeOcspResponse(): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val baos = ByteArrayOutputStream(); val dos = DataOutputStream(baos)
        // Simple ASN.1-like structure for OCSP
        dos.writeByte(0x30); dos.writeByte(0x81.toInt()); dos.writeByte(0x80.toInt()) // Sequence
        dos.writeByte(0x0a); dos.writeByte(0x01); dos.writeByte(0x00) // Enumerated: successful
        // ... more noise to look like OCSP
        dos.write(buildUdpNoise(100))
        return baos.toByteArray()
    }

    fun buildFakeCertChain(): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val baos = ByteArrayOutputStream(); val dos = DataOutputStream(baos)
        dos.writeByte(0x0b) // Handshake type: Certificate
        dos.write(byteArrayOf(0, 0, 0)) // Length (placeholder)
        dos.write(byteArrayOf(0, 0, 0)) // Cert list length (placeholder)
        repeat(2) {
            val cert = buildUdpNoise(rnd.nextInt(500, 1000))
            dos.write(byteArrayOf(0, (cert.size shr 8).toByte(), cert.size.toByte()))
            dos.write(cert)
        }
        val result = baos.toByteArray()
        val totalLen = result.size - 4
        result[1] = ((totalLen shr 16) and 0xFF).toByte(); result[2] = ((totalLen shr 8) and 0xFF).toByte(); result[3] = (totalLen and 0xFF).toByte()
        val listLen = result.size - 7
        result[4] = ((listLen shr 16) and 0xFF).toByte(); result[5] = ((listLen shr 8) and 0xFF).toByte(); result[6] = (listLen and 0xFF).toByte()
        return result
    }

    fun buildProtocolConfusion(type: String): ByteArray = when (type) {
        "SSH" -> buildSshHandshake()
        "BITTORRENT" -> "BitTorrent protocol".toByteArray() + buildUdpNoise(48)
        "HTTP" -> buildFakeHttpRequest("google.com")
        "QUIC" -> byteArrayOf(0xc0.toByte(), 0x00, 0x00, 0x00, 0x01) + buildUdpNoise(40)
        "DTLS" -> byteArrayOf(0x16, 0xfe.toByte(), 0xff.toByte()) + buildUdpNoise(24)
        else -> buildUdpNoise(64)
    }

    fun buildSshHandshake(): ByteArray = "SSH-2.0-OpenSSH_9.6p1\r\n".toByteArray()

    fun buildFakeHttpRequest(host: String, path: String = "/"): ByteArray {
        val rnd = ThreadLocalRandom.current()
        return ("GET $path HTTP/1.1\r\nHost: $host\r\nUser-Agent: ${getRandomUserAgent()}\r\nConnection: keep-alive\r\n\r\n").toByteArray()
    }

    fun getRandomUserAgent(): String = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

    fun buildQuicInitial(): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val data = ByteArray(rnd.nextInt(1200, 1280)).apply { rnd.nextBytes(this) }
        data[0] = (0xC0 or (rnd.nextInt(4) shl 4)).toByte()
        return data
    }

    fun buildQuicVersionChaos(): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)
        
        // Randomize Long Header type (0xC0 to 0xFF)
        dos.writeByte(0xC0 or rnd.nextInt(64))
        
        // Random version (not necessarily a real one)
        val versions = listOf(
            byteArrayOf(0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x01.toByte()), // QUIC v1
            byteArrayOf(0x51.toByte(), 0x30.toByte(), 0x34.toByte(), 0x33.toByte()), // Q043
            byteArrayOf(0x51.toByte(), 0x30.toByte(), 0x34.toByte(), 0x36.toByte()), // Q046
            byteArrayOf(0x51.toByte(), 0x30.toByte(), 0x35.toByte(), 0x30.toByte()), // Q050
            byteArrayOf(0xaa.toByte(), 0xaa.toByte(), 0xaa.toByte(), 0xaa.toByte()), // Reserved
            byteArrayOf(0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte())  // Version Negotiation
        )
        val ver = versions.random()
        dos.write(ver)
        
        // Random IDs
        val dcidLen = rnd.nextInt(8, 21)
        dos.writeByte(dcidLen)
        dos.write(ByteArray(dcidLen).apply { rnd.nextBytes(this) })
        
        val scidLen = rnd.nextInt(8, 21)
        dos.writeByte(scidLen)
        dos.write(ByteArray(scidLen).apply { rnd.nextBytes(this) })
        
        // Noise
        dos.write(buildUdpNoise(rnd.nextInt(10, 50)))
        
        return baos.toByteArray()
    }

    fun buildStunBindingRequest(): ByteArray {
        val baos = ByteArrayOutputStream(); val dos = DataOutputStream(baos); val rnd = ThreadLocalRandom.current()
        dos.writeShort(0x0001); dos.writeShort(0); dos.writeInt(0x2112A442)
        dos.writeLong(rnd.nextLong()); dos.writeInt(rnd.nextInt())
        return baos.toByteArray()
    }

    fun buildFakeDtlsClientHello(): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val data = ByteArray(128).apply { rnd.nextBytes(this) }
        data[0] = 0x16; data[1] = 0xfe.toByte(); data[2] = 0xff.toByte()
        return data
    }

    fun buildWireGuardHandshake(): ByteArray = buildWireguardFake()
    fun buildIkeHandshake(): ByteArray = buildUdpNoise(64)
    fun buildDhcpRequest(): ByteArray = buildUdpNoise(256)

    fun mangleSni(sni: String): String = if (ThreadLocalRandom.current().nextBoolean()) sni.lowercase() else "$sni."

    fun buildFakeTlsClientHello(host: String): ByteArray = buildFakeClientHello(host)

    fun buildFakeClientHello(sni: String, intensity: Int = 50, paddingSize: Int = 0, noMangle: Boolean = false): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val mangled = if (noMangle) sni else mangleSni(sni)
        val body = buildUdpNoise(128 + paddingSize) 
        val baos = ByteArrayOutputStream(); val dos = DataOutputStream(baos)
        dos.writeByte(0x16); dos.writeShort(0x0301); dos.writeShort(body.size + 4)
        dos.writeByte(0x01); dos.writeByte(0x00); dos.writeShort(body.size); dos.write(body)
        return baos.toByteArray()
    }

    fun buildQuicVersionNegotiation(): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val baos = ByteArrayOutputStream(); val dos = DataOutputStream(baos)
        dos.writeByte(0xC0 or rnd.nextInt(64)); dos.writeInt(0)
        dos.writeByte(8); dos.write(buildUdpNoise(8)); dos.writeByte(8); dos.write(buildUdpNoise(8))
        repeat(3) { dos.writeInt(rnd.nextInt()) }
        return baos.toByteArray()
    }

    fun buildQuicInitialFake(): ByteArray = buildQuicInitial()
    
    fun buildChromeHello(sni: String): ByteArray = buildFakeClientHello(sni, 70, 500, true)
    fun buildFirefoxHello(sni: String): ByteArray = buildFakeClientHello(sni, 60, 400, true)
    fun buildTls13Hello(sni: String): ByteArray = buildFakeClientHello(sni, 80, 600, true)
    fun buildSafariHello(sni: String): ByteArray = buildFakeClientHello(sni, 50, 300, true)

    fun addTlsGreaseExtensions(data: ByteArray, length: Int): ByteArray = injectExtension(data, length, 0x1a1a, buildUdpNoise(2))

    fun moveSniExtensionToEnd(data: ByteArray, length: Int): ByteArray {
        if (length < 44 || data[0] != 0x16.toByte()) return data.copyOf(length)
        try {
            var pos = 5 + 4 + 2 + 32 
            val sidLen = data[pos].toInt() and 0xFF; pos += 1 + sidLen
            val cipherLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF); pos += 2 + cipherLen
            val compLen = data[pos].toInt() and 0xFF; pos += 1 + compLen
            if (pos >= length - 2) return data.copyOf(length)
            
            val extLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos+1].toInt() and 0xFF)
            if (pos + 2 + extLen > length) return data.copyOf(length)
            
            val extensions = mutableListOf<Pair<Int, ByteArray>>()
            var ePos = pos + 2
            val end = ePos + extLen
            
            var sni: ByteArray? = null
            while (ePos + 4 <= end) {
                val type = ((data[ePos].toInt() and 0xFF) shl 8) or (data[ePos+1].toInt() and 0xFF)
                val len = ((data[ePos+2].toInt() and 0xFF) shl 8) or (data[ePos+3].toInt() and 0xFF)
                val body = data.copyOfRange(ePos + 4, minOf(ePos + 4 + len, end))
                if (type == 0) sni = body else extensions.add(type to body)
                ePos += 4 + len
            }
            
            if (sni == null) return data.copyOf(length)
            extensions.add(0 to sni) // Add SNI at the end
            
            val baos = ByteArrayOutputStream(); val dos = DataOutputStream(baos)
            dos.write(data, 0, pos)
            val newExtsBaos = ByteArrayOutputStream(); val newExtsDos = DataOutputStream(newExtsBaos)
            for (ext in extensions) {
                newExtsDos.writeShort(ext.first); newExtsDos.writeShort(ext.second.size); newExtsDos.write(ext.second)
            }
            val newExts = newExtsBaos.toByteArray()
            dos.writeShort(newExts.size); dos.write(newExts)
            
            val result = baos.toByteArray()
            updateTlsLengths(result)
            return result
        } catch (e: Exception) { return data.copyOf(length) }
    }

    fun shuffleTlsExtensions(data: ByteArray, length: Int): ByteArray {
        if (length < 44 || data[0] != 0x16.toByte()) return data.copyOf(length)
        try {
            var pos = 5 + 4 + 2 + 32 
            val sidLen = data[pos].toInt() and 0xFF; pos += 1 + sidLen
            val cipherLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF); pos += 2 + cipherLen
            val compLen = data[pos].toInt() and 0xFF; pos += 1 + compLen
            if (pos >= length - 2) return data.copyOf(length)
            
            val extLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos+1].toInt() and 0xFF)
            if (pos + 2 + extLen > length) return data.copyOf(length)
            
            val extensions = mutableListOf<Pair<Int, ByteArray>>()
            var ePos = pos + 2
            val end = ePos + extLen
            while (ePos + 4 <= end) {
                val type = ((data[ePos].toInt() and 0xFF) shl 8) or (data[ePos+1].toInt() and 0xFF)
                val len = ((data[ePos+2].toInt() and 0xFF) shl 8) or (data[ePos+3].toInt() and 0xFF)
                extensions.add(type to data.copyOfRange(ePos + 4, minOf(ePos + 4 + len, end)))
                ePos += 4 + len
            }
            
            extensions.shuffle()
            
            val baos = ByteArrayOutputStream(); val dos = DataOutputStream(baos)
            dos.write(data, 0, pos)
            val newExtsBaos = ByteArrayOutputStream(); val newExtsDos = DataOutputStream(newExtsBaos)
            for (ext in extensions) {
                newExtsDos.writeShort(ext.first); newExtsDos.writeShort(ext.second.size); newExtsDos.write(ext.second)
            }
            val newExts = newExtsBaos.toByteArray()
            dos.writeShort(newExts.size); dos.write(newExts)
            
            val result = baos.toByteArray()
            updateTlsLengths(result)
            return result
        } catch (e: Exception) { return data.copyOf(length) }
    }

    private fun updateTlsLengths(result: ByteArray) {
        val recLen = result.size - 5
        result[3] = ((recLen shr 8) and 0xFF).toByte(); result[4] = (recLen and 0xFF).toByte()
        val handLen = result.size - 9
        result[6] = ((handLen shr 16) and 0xFF).toByte(); result[7] = ((handLen shr 8) and 0xFF).toByte(); result[8] = (handLen and 0xFF).toByte()
    }

    fun buildHttp2SettingsFake(): ByteArray {
        val baos = ByteArrayOutputStream(); val dos = DataOutputStream(baos)
        // HTTP/2 Frame Header: 24-bit length (6), 8-bit type (SETTINGS=0x04), 8-bit flags (0x00), 31-bit stream id (0)
        dos.write(byteArrayOf(0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00))
        // Settings: identifier (0x0001 = SETTINGS_HEADER_TABLE_SIZE), value (4096)
        dos.writeShort(0x0001); dos.writeInt(4096)
        return baos.toByteArray()
    }

    fun buildQuicCryptoFake(): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val baos = ByteArrayOutputStream(); val dos = DataOutputStream(baos)
        // QUIC Long Header Initial: Type (0xC0), Version (1)
        dos.writeByte(0xC0); dos.writeInt(0x00000001)
        // DCID, SCID len
        dos.writeByte(0x08); dos.write(buildUdpNoise(8))
        dos.writeByte(0x08); dos.write(buildUdpNoise(8))
        // Token len (0)
        dos.writeByte(0x00)
        // Length (fake)
        dos.writeShort(0x4400) 
        // Crypto Frame: Type (0x06), Offset (0), Length (128)
        dos.writeByte(0x06); dos.writeByte(0x00); dos.writeShort(128)
        dos.write(buildUdpNoise(128))
        return baos.toByteArray()
    }

    fun buildDnsFakeQuery(domain: String = "google.com"): ByteArray {
        val baos = ByteArrayOutputStream(); val dos = DataOutputStream(baos)
        val rnd = ThreadLocalRandom.current()
        dos.writeShort(rnd.nextInt(65535)) // ID
        dos.writeShort(0x0100) // Flags: Standard query
        dos.writeShort(0x0001) // Questions: 1
        dos.writeShort(0x0000) // Answer RRs: 0
        dos.writeShort(0x0000) // Authority RRs: 0
        dos.writeShort(0x0000) // Additional RRs: 0
        
        // Question
        domain.split(".").forEach { part ->
            dos.writeByte(part.length)
            dos.write(part.toByteArray())
        }
        dos.writeByte(0)
        dos.writeShort(0x0001) // Type: A
        dos.writeShort(0x0001) // Class: IN
        return baos.toByteArray()
    }

    fun buildEdgeHello(sni: String): ByteArray = buildFakeClientHello(sni, 110, 450, true)
    fun buildOperaHello(sni: String): ByteArray = buildFakeClientHello(sni, 105, 420, true)

    fun buildFakeEchExtension(): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val b = ByteArray(rnd.nextInt(128, 256))
        rnd.nextBytes(b)
        // Simple ECH extension payload: version + config_id + enc + payload
        b[0] = 0xfe.toByte(); b[1] = 0x0d.toByte() 
        return b
    }

    fun buildTlsNoise(size: Int): ByteArray {
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)
        dos.writeByte(23)
        dos.writeShort(0x0303)
        dos.writeShort(size)
        dos.write(buildUdpNoise(size))
        return baos.toByteArray()
    }

    fun buildFakeTlsHandshakeWithConfusion(sni: String): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val baos = ByteArrayOutputStream()
        // 1. SSH banner
        baos.write(buildSshHandshake())
        // 2. HTTP request (truncated or fake)
        baos.write("GET / HTTP/1.1\r\nHost: $sni\r\n\r\n".toByteArray())
        // 3. Real-looking TLS ClientHello
        baos.write(buildRealisticTlsHello(sni))
        return baos.toByteArray()
    }

    fun injectTlsPadding(data: ByteArray, length: Int, padSize: Int): ByteArray {
        if (length < 44 || data[0] != 0x16.toByte()) return data.copyOf(length)
        val padding = ByteArray(padSize.coerceIn(1, 2048))
        return injectExtension(data, length, 0x0015, padding)
    }

    fun injectTlsGrease(data: ByteArray, length: Int): ByteArray = addTlsGreaseExtensions(data, length)
    fun buildFakeWebSocketHandshake(host: String): ByteArray = buildFakeHttpRequest(host, "/chat")
    fun buildHttp2PreambleFake(): ByteArray = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray()
    fun buildMultiSniHello(sni: String): ByteArray = buildFakeClientHello(sni, 90, 800, false)
    fun buildRealisticTlsHello(sni: String): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val baos = ByteArrayOutputStream(); val dos = DataOutputStream(baos)
        
        // Content Type: Handshake (22), Version: TLS 1.2 (0x0303)
        dos.writeByte(22); dos.writeShort(0x0303)
        
        val handBaos = ByteArrayOutputStream(); val handDos = DataOutputStream(handBaos)
        // Handshake Type: Client Hello (1)
        handDos.writeByte(1)
        // Length (3 bytes, placeholder)
        handDos.write(byteArrayOf(0, 0, 0))
        // Version: TLS 1.2 (0x0303)
        handDos.writeShort(0x0303)
        // Random (32 bytes)
        handDos.write(ByteArray(32).apply { rnd.nextBytes(this) })
        // Session ID Length (0)
        handDos.writeByte(0)
        // Cipher Suites
        val ciphers = byteArrayOf(
            0x13.toByte(), 0x01.toByte(), // TLS_AES_128_GCM_SHA256
            0x13.toByte(), 0x02.toByte(), // TLS_AES_256_GCM_SHA384
            0x13.toByte(), 0x03.toByte(), // TLS_CHACHA20_POLY1305_SHA256
            0xc0.toByte(), 0x2b.toByte(), // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc0.toByte(), 0x2f.toByte()  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        )
        handDos.writeShort(ciphers.size); handDos.write(ciphers)
        // Compression Methods (1: null)
        handDos.writeByte(1); handDos.writeByte(0)
        
        // Extensions
        val extBaos = ByteArrayOutputStream(); val extDos = DataOutputStream(extBaos)
        extDos.write(buildSniExtension(sni))
        // Supported Groups (10)
        extDos.writeShort(10); extDos.writeShort(4); extDos.writeShort(2); extDos.writeShort(0x0017) // x25519
        // Supported Versions (43)
        extDos.writeShort(43); extDos.writeShort(3); extDos.writeByte(2); extDos.writeShort(0x0304) // TLS 1.3
        
        val exts = extBaos.toByteArray()
        handDos.writeShort(exts.size); handDos.write(exts)
        
        val handshake = handBaos.toByteArray()
        val hLen = handshake.size - 4
        handshake[1] = ((hLen shr 16) and 0xFF).toByte()
        handshake[2] = ((hLen shr 8) and 0xFF).toByte()
        handshake[3] = (hLen and 0xFF).toByte()
        
        dos.writeShort(handshake.size)
        dos.write(handshake)
        return baos.toByteArray()
    }

    fun buildRealisticHttpReq(host: String): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val methods = listOf("GET", "POST", "HEAD", "OPTIONS")
        val paths = listOf("/", "/index.html", "/api/v1/status", "/favicon.ico")
        val method = methods.random()
        val path = paths.random()
        val ua = getRandomUserAgent()
        
        return ("$method $path HTTP/1.1\r\n" +
                "Host: $host\r\n" +
                "User-Agent: $ua\r\n" +
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n" +
                "Accept-Language: en-US,en;q=0.5\r\n" +
                "Accept-Encoding: gzip, deflate, br\r\n" +
                "Connection: keep-alive\r\n" +
                "Upgrade-Insecure-Requests: 1\r\n" +
                "Sec-Fetch-Dest: document\r\n" +
                "Sec-Fetch-Mode: navigate\r\n" +
                "Sec-Fetch-Site: none\r\n" +
                "Sec-Fetch-User: ?1\r\n" +
                "\r\n").toByteArray()
    }
    fun buildFakeUdpPacket(size: Int): ByteArray = buildUdpNoise(size)
    fun mangleHttpMethod(data: ByteArray, length: Int): ByteArray {
        if (length < 8) return data.copyOf(length)
        val copy = data.copyOf(length)
        var spaceIdx = -1
        for (i in 0 until minOf(length, 10)) {
            if (data[i] == ' '.code.toByte()) {
                spaceIdx = i
                break
            }
        }
        if (spaceIdx != -1) {
            val rnd = ThreadLocalRandom.current()
            if (rnd.nextBoolean()) {
                for (i in 0 until spaceIdx) {
                    if (rnd.nextBoolean()) {
                        val c = copy[i]
                        if (c in 'A'.code.toByte()..'Z'.code.toByte()) {
                            copy[i] = (c + 32).toByte()
                        } else if (c in 'a'.code.toByte()..'z'.code.toByte()) {
                            copy[i] = (c - 32).toByte()
                        }
                    }
                }
            }
        }
        return copy
    }

    fun addSpaceToHttpMethod(data: ByteArray, length: Int): ByteArray {
        if (length < 8) return data.copyOf(length)
        var spaceIdx = -1
        for (i in 0 until minOf(length, 12)) {
            if (data[i] == ' '.code.toByte()) {
                spaceIdx = i
                break
            }
        }
        if (spaceIdx != -1) {
            val result = ByteArray(length + 1)
            System.arraycopy(data, 0, result, 0, spaceIdx + 1)
            result[spaceIdx + 1] = ' '.code.toByte()
            System.arraycopy(data, spaceIdx + 1, result, spaceIdx + 2, length - (spaceIdx + 1))
            return result
        }
        return data.copyOf(length)
    }

    fun mangleHttpMethodCase(data: ByteArray, length: Int): ByteArray {
        if (length < 8) return data.copyOf(length)
        val copy = data.copyOf(length)
        // Only mangle first few bytes (the method)
        for (i in 0 until minOf(length, 6)) {
            if (copy[i] in 'a'.code.toByte()..'z'.code.toByte()) {
                copy[i] = (copy[i] - 32).toByte()
            } else if (copy[i] in 'A'.code.toByte()..'Z'.code.toByte()) {
                if (ThreadLocalRandom.current().nextBoolean()) {
                    copy[i] = (copy[i] + 32).toByte()
                }
            }
        }
        return copy
    }

    fun addDotToHost(data: ByteArray, length: Int): ByteArray {
        val hostPrefix = byteArrayOf('H'.code.toByte(), 'o'.code.toByte(), 's'.code.toByte(), 't'.code.toByte(), ':'.code.toByte())
        val hostPrefixLower = byteArrayOf('h'.code.toByte(), 'o'.code.toByte(), 's'.code.toByte(), 't'.code.toByte(), ':'.code.toByte())
        
        var matchIdx = 0
        var foundHost = false
        var insertPos = -1
        
        for (i in 0 until length - 1) {
            if (!foundHost) {
                if (data[i] == hostPrefix[matchIdx] || data[i] == hostPrefixLower[matchIdx]) {
                    matchIdx++
                    if (matchIdx == hostPrefix.size) {
                        foundHost = true
                    }
                } else {
                    matchIdx = 0
                    // if it was newline, we could start matching on next
                    if (data[i] == '\n'.code.toByte() && (data[i+1] == 'H'.code.toByte() || data[i+1] == 'h'.code.toByte())) {
                        matchIdx = 0
                    }
                }
            } else {
                if (data[i] == '\r'.code.toByte() && data[i+1] == '\n'.code.toByte()) {
                    insertPos = i
                    break
                }
            }
        }
        
        if (insertPos != -1) {
            val result = ByteArray(length + 1)
            System.arraycopy(data, 0, result, 0, insertPos)
            result[insertPos] = '.'.code.toByte()
            System.arraycopy(data, insertPos, result, insertPos + 1, length - insertPos)
            return result
        }
        return data.copyOf(length)
    }
    fun injectLargeGrease(data: ByteArray, length: Int, greaseLen: Int = 1500): ByteArray = injectExtension(data, length, 0x4a4a, buildUdpNoise(greaseLen))
    
    fun padTlsRecord(data: ByteArray, length: Int, targetLen: Int = 1400): ByteArray {
        if (length < 5 || data[0] != 0x16.toByte()) return data.copyOf(length)
        val rnd = ThreadLocalRandom.current()
        val currentLen = ((data[3].toInt() and 0xFF) shl 8) or (data[4].toInt() and 0xFF)
        if (currentLen + 5 != length) return data.copyOf(length) // Not a single complete record
        
        val paddingNeeded = targetLen - length
        if (paddingNeeded <= 0) return data.copyOf(length)
        
        val baos = ByteArrayOutputStream()
        baos.write(data, 0, length)
        // Add padding record (Application Data with junk)
        baos.write(0x17) // Content Type: App Data
        baos.write(0x03); baos.write(0x03) // Version 1.2
        baos.write((paddingNeeded shr 8) and 0xFF)
        baos.write(paddingNeeded and 0xFF)
        baos.write(buildUdpNoise(paddingNeeded))
        return baos.toByteArray()
    }

    fun randomizeHeaderCase(data: ByteArray, length: Int): ByteArray {
        val copy = data.copyOf(length)
        val rnd = ThreadLocalRandom.current()
        var inHeaderName = false
        var afterRequestLine = false
        for (i in 0 until length) {
            val b = copy[i]
            if (!afterRequestLine) {
                if (b == '\n'.code.toByte()) {
                    afterRequestLine = true
                    inHeaderName = true
                }
                continue
            }
            if (inHeaderName) {
                if (b == ':'.code.toByte()) {
                    inHeaderName = false
                } else if (b in 'a'.code.toByte()..'z'.code.toByte() || b in 'A'.code.toByte()..'Z'.code.toByte()) {
                    if (rnd.nextBoolean()) {
                        if (b in 'a'.code.toByte()..'z'.code.toByte()) {
                            copy[i] = (b - 32).toByte()
                        } else {
                            copy[i] = (b + 32).toByte()
                        }
                    }
                } else if (b == '\n'.code.toByte()) {
                    // Next line
                    inHeaderName = true
                }
            } else {
                if (b == '\n'.code.toByte()) {
                    inHeaderName = true
                }
            }
        }
        return copy
    }

    fun injectMultiTlsPadding(data: ByteArray, length: Int, count: Int): ByteArray {
        var currentData = data
        var currentLen = length
        val rnd = ThreadLocalRandom.current()
        repeat(count) {
            val padSize = rnd.nextInt(16, 64)
            currentData = injectExtension(currentData, currentLen, 0x0015, ByteArray(padSize))
            currentLen = currentData.size
        }
        return currentData
    }

    fun splitTlsRecords(data: ByteArray, length: Int, splitPos: Int): ByteArray {
        if (length < 5 || splitPos < 5 || splitPos >= length) return data.copyOf(length)
        try {
            val baos = java.io.ByteArrayOutputStream()
            // First record
            baos.write(data[0].toInt()); baos.write(data[1].toInt()); baos.write(data[2].toInt())
            val len1 = splitPos - 5
            baos.write((len1 shr 8) and 0xFF); baos.write(len1 and 0xFF)
            baos.write(data, 5, len1)
            
            // Second record
            baos.write(data[0].toInt()); baos.write(data[1].toInt()); baos.write(data[2].toInt())
            val len2 = length - splitPos
            baos.write((len2 shr 8) and 0xFF); baos.write(len2 and 0xFF)
            baos.write(data, splitPos, len2)
            
            return baos.toByteArray()
        } catch (e: Exception) { return data.copyOf(length) }
    }

    fun buildQuicJitterPad(targetSize: Int): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val data = ByteArray(targetSize)
        rnd.nextBytes(data)
        // QUIC Long Header Initial packet minimal indicators if needed, 
        // but for noise padding we just need the size to be variable.
        return data
    }

    fun buildTlsHeartbeat(): ByteArray {
        // TLS Heartbeat (RFC 6520) - often blocked if suspicious, but can "kick" buffers
        val res = ByteArray(19)
        res[0] = 0x18 // Heartbeat
        res[1] = 0x03
        res[2] = 0x03
        res[3] = 0x00
        res[4] = 0x0E
        res[5] = 0x01 // Request
        res[6] = 0x00
        res[7] = 0x03 // Payload length
        // Fake payload and padding
        ThreadLocalRandom.current().nextBytes(res.sliceArray(8 until res.size))
        return res
    }
}
