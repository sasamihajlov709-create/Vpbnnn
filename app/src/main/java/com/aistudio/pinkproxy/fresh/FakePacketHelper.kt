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

    fun buildOpenVpnFake(): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val baos = ByteArrayOutputStream(); val dos = DataOutputStream(baos)
        dos.writeByte((0x07 shl 3) or 0x00)
        dos.write(ByteArray(8).apply { rnd.nextBytes(this) })
        dos.writeByte(0x00); dos.writeInt(rnd.nextInt()); dos.writeInt((System.currentTimeMillis() / 1000).toInt())
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
    fun injectTlsPadding(data: ByteArray, length: Int, size: Int): ByteArray = injectExtension(data, length, 0x0015, ByteArray(size))
    fun injectTlsGrease(data: ByteArray, length: Int): ByteArray = addTlsGreaseExtensions(data, length)
    fun buildFakeWebSocketHandshake(host: String): ByteArray = buildFakeHttpRequest(host, "/chat")
    fun buildHttp2PreambleFake(): ByteArray = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray()
    fun buildMultiSniHello(sni: String): ByteArray = buildFakeClientHello(sni, 90, 800, false)
    fun buildFakeUdpPacket(size: Int): ByteArray = buildUdpNoise(size)
    fun mangleHttpMethod(data: ByteArray, length: Int): ByteArray {
        if (length < 8) return data.copyOf(length)
        val copy = data.copyOf(length)
        val s = String(data, 0, minOf(length, 10), Charsets.US_ASCII)
        val spaceIdx = s.indexOf(' ')
        if (spaceIdx != -1) {
            val method = s.substring(0, spaceIdx)
            val rnd = ThreadLocalRandom.current()
            if (rnd.nextBoolean()) {
                // Change case: GET -> gEt
                for (i in 0 until method.length) {
                    if (rnd.nextBoolean()) {
                        val c = method[i]
                        copy[i] = if (c.isUpperCase()) c.lowercaseChar().code.toByte() else c.uppercaseChar().code.toByte()
                    }
                }
            }
        }
        return copy
    }

    fun addSpaceToHttpMethod(data: ByteArray, length: Int): ByteArray {
        if (length < 8) return data.copyOf(length)
        val s = String(data, 0, minOf(length, 12), Charsets.US_ASCII)
        val spaceIdx = s.indexOf(' ')
        if (spaceIdx != -1) {
            val baos = ByteArrayOutputStream()
            baos.write(data, 0, spaceIdx + 1)
            baos.write(' '.code) // Extra space
            baos.write(data, spaceIdx + 1, length - (spaceIdx + 1))
            return baos.toByteArray()
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
        val s = String(data, 0, length, Charsets.US_ASCII)
        val hostLine = s.lines().find { it.startsWith("Host:", true) }
        if (hostLine != null) {
            val start = s.indexOf(hostLine)
            val end = start + hostLine.length
            val baos = ByteArrayOutputStream()
            baos.write(data, 0, end)
            baos.write('.'.code) // Dot after host
            baos.write(data, end, length - end)
            return baos.toByteArray()
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
        val s = String(data, 0, length, StandardCharsets.US_ASCII)
        val lines = s.split("\r\n").toMutableList()
        val rnd = ThreadLocalRandom.current()
        
        for (i in 1 until lines.size) { // Skip request line
            val line = lines[i]
            if (line.isEmpty()) break // End of headers
            val colonIdx = line.indexOf(':')
            if (colonIdx != -1) {
                val name = line.substring(0, colonIdx)
                val value = line.substring(colonIdx)
                val newName = name.toCharArray().map {
                    if (rnd.nextBoolean()) it.lowercaseChar() else it.uppercaseChar()
                }.joinToString("")
                lines[i] = newName + value
            }
        }
        return lines.joinToString("\r\n").toByteArray(StandardCharsets.US_ASCII)
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
        if (length < 10) return data.copyOf(length)
        val res = ByteArray(length + 5)
        System.arraycopy(data, 0, res, 0, splitPos)
        System.arraycopy(data, 0, res, splitPos, 5)
        System.arraycopy(data, splitPos, res, splitPos + 5, length - splitPos)
        return res
    }
}
