package com.aistudio.pinkproxy.fresh

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.util.concurrent.ThreadLocalRandom
import java.nio.charset.StandardCharsets
import java.nio.ByteBuffer
import android.util.Base64

object FakePacketHelper {
    private var _staticNoiseCache: ByteArray? = null
    private fun getStaticNoise(): ByteArray {
        var res = _staticNoiseCache
        if (res == null) {
            val newCache = ByteArray(32768)
            java.util.concurrent.ThreadLocalRandom.current().nextBytes(newCache)
            _staticNoiseCache = newCache
            res = newCache
        }
        return res
    }
    
    private var _cachedQuicInitial: ByteArray? = null
    private var _cachedStun: ByteArray? = null
    private var _cachedDtls: ByteArray? = null
    private var _cachedWg: ByteArray? = null
    private var _cachedIke: ByteArray? = null
    private var _cachedDhcp: ByteArray? = null
    
    private fun getQuicInitial() = _cachedQuicInitial ?: buildQuicInitial().also { _cachedQuicInitial = it }
    private fun getStun() = _cachedStun ?: buildStunBindingRequest().also { _cachedStun = it }
    private fun getDtls() = _cachedDtls ?: buildFakeDtlsClientHello().also { _cachedDtls = it }
    private fun getWg() = _cachedWg ?: buildWireGuardHandshake().also { _cachedWg = it }
    private fun getIke() = _cachedIke ?: buildIkeHandshake().also { _cachedIke = it }
    private fun getDhcp() = _cachedDhcp ?: buildDhcpRequest().also { _cachedDhcp = it }
    
    private var cacheTime = System.currentTimeMillis()
    
    // Pre-allocated reusable buffer for common packet construction to avoid GC
    private val threadLocalBuffer = object : ThreadLocal<ByteBuffer>() {
        override fun initialValue(): ByteBuffer = ByteBuffer.allocate(65536)
    }

    private fun getBuffer(): ByteBuffer {
        val buf = threadLocalBuffer.get() ?: ByteBuffer.allocate(65536).also { threadLocalBuffer.set(it) }
        buf.clear()
        return buf
    }

    private fun checkCacheRefresh() {
        if (System.currentTimeMillis() - cacheTime > 30000) {
            _cachedQuicInitial = buildQuicInitial()
            _cachedStun = buildStunBindingRequest()
            _cachedDtls = buildFakeDtlsClientHello()
            _cachedWg = buildWireGuardHandshake()
            _cachedIke = buildIkeHandshake()
            _cachedDhcp = buildDhcpRequest()
            cacheTime = System.currentTimeMillis()
        }
    }
    
    fun getCachedQuicInitial() = synchronized(this) { checkCacheRefresh(); getQuicInitial() }
    fun getCachedStun() = synchronized(this) { checkCacheRefresh(); getStun() }
    fun getCachedDtls() = synchronized(this) { checkCacheRefresh(); getDtls() }
    fun getCachedWg() = synchronized(this) { checkCacheRefresh(); getWg() }
    fun getCachedIke() = synchronized(this) { checkCacheRefresh(); getIke() }
    fun getCachedDhcp() = synchronized(this) { checkCacheRefresh(); getDhcp() }

    fun buildExtension(type: Int, data: ByteArray): ByteArray {
        val buf = ByteBuffer.allocate(4 + data.size)
        buf.putShort(type.toShort())
        buf.putShort(data.size.toShort())
        buf.put(data)
        return buf.array()
    }

    fun buildSniExtension(host: String): ByteArray {
        val hostBytes = host.toByteArray(StandardCharsets.UTF_8)
        val buf = ByteBuffer.allocate(hostBytes.size + 5)
        buf.putShort((hostBytes.size + 3).toShort()) // Server Name List length
        buf.put(0) // Name type: host_name
        buf.putShort(hostBytes.size.toShort()) // Host name length
        buf.put(hostBytes)
        return buf.array()
    }

    fun injectExtension(data: ByteArray, length: Int, type: Int, extData: ByteArray): ByteArray {
        if (length < 44 || data[0] != 0x16.toByte()) return data.copyOf(length)
        try {
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
            if (length < pos + 2) return data.copyOf(length)
            
            val oldExtLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos+1].toInt() and 0xFF)
            if (pos + 2 + oldExtLen > length) return data.copyOf(length)
            
            val result = ByteArray(pos + 2 + oldExtLen + 4 + extData.size)
            System.arraycopy(data, 0, result, 0, pos)
            
            val newExtLen = oldExtLen + 4 + extData.size
            result[pos] = (newExtLen shr 8).toByte()
            result[pos + 1] = (newExtLen and 0xFF).toByte()
            
            if (oldExtLen > 0) {
                System.arraycopy(data, pos + 2, result, pos + 2, oldExtLen)
            }
            
            val extStart = pos + 2 + oldExtLen
            result[extStart] = (type shr 8).toByte()
            result[extStart + 1] = (type and 0xFF).toByte()
            result[extStart + 2] = (extData.size shr 8).toByte()
            result[extStart + 3] = (extData.size and 0xFF).toByte()
            System.arraycopy(extData, 0, result, extStart + 4, extData.size)
            
            // Fix lengths
            val recLen = result.size - 5
            result[3] = (recLen shr 8).toByte(); result[4] = (recLen and 0xFF).toByte()
            val handLen = result.size - 9
            result[6] = (handLen shr 16).toByte(); result[7] = (handLen shr 8).toByte(); result[8] = (handLen and 0xFF).toByte()
            
            return result
        } catch (e: Exception) { return data.copyOf(length) }
    }

    fun buildWireguardFake(): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val data = ByteArray(148)
        data[0] = 0x01
        // Indices 1,2,3 are 0
        val buf = ByteBuffer.wrap(data)
        buf.position(4)
        buf.putInt(rnd.nextInt()) // Sender Index
        
        val rndBytes = ByteArray(32)
        rnd.nextBytes(rndBytes); System.arraycopy(rndBytes, 0, data, 8, 32) // Unencrypted Ephemeral
        
        val rndBytes48 = ByteArray(48)
        rnd.nextBytes(rndBytes48); System.arraycopy(rndBytes48, 0, data, 40, 48) // Encrypted Static
        
        val rndBytes28 = ByteArray(28)
        rnd.nextBytes(rndBytes28); System.arraycopy(rndBytes28, 0, data, 88, 28) // Encrypted Timestamp
        
        val rndBytes16 = ByteArray(16)
        rnd.nextBytes(rndBytes16); System.arraycopy(rndBytes16, 0, data, 116, 16) // MAC1
        rnd.nextBytes(rndBytes16); System.arraycopy(rndBytes16, 0, data, 132, 16) // MAC2
        
        return data
    }

    fun buildDecoyHttpResponse(): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val statuses = listOf("200 OK", "404 Not Found", "302 Found", "301 Moved Permanently")
        val contentTypes = listOf("text/html", "application/json", "image/png", "text/plain")
        val status = statuses.random()
        val ct = contentTypes.random()
        val body = buildUdpNoise(rnd.nextInt(20, 100))
        val header = ("HTTP/1.1 $status\r\n" +
                "Content-Type: $ct\r\n" +
                "Content-Length: ${body.size}\r\n" +
                "Connection: close\r\n\r\n").toByteArray()
        val result = ByteArray(header.size + body.size)
        System.arraycopy(header, 0, result, 0, header.size)
        System.arraycopy(body, 0, result, header.size, body.size)
        return result
    }

    fun buildHandshakeCombo(noiseSize: Int = 64): ByteArray {
        val rnd = ThreadLocalRandom.current()
        return when (rnd.nextInt(3)) {
            0 -> {
                val s1 = buildSshHandshake()
                val s2 = "\r\n".toByteArray()
                val s3 = buildFakeHttpRequest("google.com")
                val res = ByteArray(s1.size + s2.size + s3.size)
                System.arraycopy(s1, 0, res, 0, s1.size)
                System.arraycopy(s2, 0, res, s1.size, s2.size)
                System.arraycopy(s3, 0, res, s1.size + s2.size, s3.size)
                res
            }
            1 -> {
                val s1 = buildRealisticTlsHello("youtube.com")
                val s2 = buildUdpNoise(noiseSize)
                val res = ByteArray(s1.size + s2.size)
                System.arraycopy(s1, 0, res, 0, s1.size)
                System.arraycopy(s2, 0, res, s1.size, s2.size)
                res
            }
            else -> {
                val s1 = byteArrayOf(0x00, 0x00, 0x00, 0x01)
                val s2 = buildSshHandshake()
                val s3 = buildUdpNoise(noiseSize / 2)
                val res = ByteArray(s1.size + s2.size + s3.size)
                System.arraycopy(s1, 0, res, 0, s1.size)
                System.arraycopy(s2, 0, res, s1.size, s2.size)
                System.arraycopy(s3, 0, res, s1.size + s2.size, s3.size)
                res
            }
        }
    }

    fun injectGrease(data: ByteArray, length: Int): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val grease = ByteArray(rnd.nextInt(2, 8))
        rnd.nextBytes(grease)
        return injectExtension(data, length, 0x1a1a + rnd.nextInt(0, 10) * 0x1111, grease)
    }

    fun injectEchGrease(data: ByteArray, length: Int): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val grease = buildUdpNoise(rnd.nextInt(128, 256))
        return injectExtension(data, length, 0xfe0d, grease)
    }

    fun buildOpenVpnFake(): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val data = ByteArray(14)
        data[0] = ((0x07 shl 3) or 0x00).toByte()
        val rndBytes = ByteArray(8); rnd.nextBytes(rndBytes); System.arraycopy(rndBytes, 0, data, 1, 8)
        data[9] = 0x00
        val buf = ByteBuffer.wrap(data)
        buf.position(10)
        buf.putInt(rnd.nextInt())
        // Missing the 4 bytes for timestamp in original 14 byte calculation, it was 1 + 8 + 1 + 4 + 4 = 18 bytes really
        val realData = ByteArray(18)
        System.arraycopy(data, 0, realData, 0, 14)
        val buf2 = ByteBuffer.wrap(realData)
        buf2.position(14)
        buf2.putInt((System.currentTimeMillis() / 1000).toInt())
        return realData
    }

    fun buildQuicInitialReal(dcid: ByteArray, scid: ByteArray, payload: ByteArray): ByteArray {
        val len = payload.size + 4 
        val varIntSize = if (len < 64) 1 else 2
        val totalSize = 1 + 4 + 1 + dcid.size + 1 + scid.size + 1 + varIntSize + 4 + payload.size
        val data = ByteArray(totalSize)
        val buf = ByteBuffer.wrap(data)
        buf.put(0xC3.toByte())
        buf.putInt(0x00000001)
        buf.put(dcid.size.toByte()); buf.put(dcid)
        buf.put(scid.size.toByte()); buf.put(scid)
        buf.put(0x00.toByte()) // Token length
        
        if (len < 64) buf.put(len.toByte())
        else {
            buf.put((0x40 or (len shr 8)).toByte())
            buf.put((len and 0xFF).toByte())
        }
        
        buf.putInt(ThreadLocalRandom.current().nextInt())
        buf.put(payload)
        return data
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
                if (sidLen > 0 && sidLen <= 32 && sidLenOffset + 1 + sidLen <= length) {
                    val rnd = ThreadLocalRandom.current()
                    for (i in 0 until sidLen) copy[sidLenOffset + 1 + i] = rnd.nextInt(256).toByte()
                }
            }
        } catch (e: Throwable) {}
        return copy
    }

    fun buildUdpNoise(size: Int): ByteArray {
        val result = ByteArray(size)
        val cache = getStaticNoise()
        if (size <= 32768) {
            val offset = java.util.concurrent.ThreadLocalRandom.current().nextInt(0, 32768 - size + 1)
            System.arraycopy(cache, offset, result, 0, size)
        } else {
            java.util.concurrent.ThreadLocalRandom.current().nextBytes(result)
        }
        return result
    }

    fun injectMultipleSni(data: ByteArray, length: Int, host: String): ByteArray {
        if (length < 44 || data[0] != 0x16.toByte()) return data.copyOf(length)
        try {
            val rnd = ThreadLocalRandom.current()
            val fakeSnis = listOf("google.com", "bing.com", "apple.com", "microsoft.com", "cloudflare.com")
            
            var current = data.copyOf(length)
            repeat(rnd.nextInt(1, 3)) {
                val fake = fakeSnis.random()
                val sniExt = buildSniExtension(fake)
                current = injectExtension(current, current.size, 0x0000, sniExt)
            }
            
            val realSniExt = buildSniExtension(host)
            current = injectExtension(current, current.size, 0x0000, realSniExt)
            
            updateTlsLengths(current)
            return current
        } catch (e: Exception) {
            return data.copyOf(length)
        }
    }
    
    private fun updateTlsLengths(data: ByteArray) {
        if (data.size < 9) return
        val recLen = data.size - 5
        data[3] = (recLen shr 8).toByte()
        data[4] = (recLen and 0xFF).toByte()
        val handLen = data.size - 9
        data[6] = (handLen shr 16).toByte()
        data[7] = (handLen shr 8).toByte()
        data[8] = (handLen and 0xFF).toByte()
    }

    fun buildEchFakeRecord(host: String): ByteArray {
        val rnd = ThreadLocalRandom.current()
        // Complex nesting, using simplified ByteBuffer build
        val sni = buildSniExtension(listOf("google.com", "cloudflare.com").random())
        val ech = buildUdpNoise(rnd.nextInt(128, 256))
        
        val extsLen = (sni.size + 4) + (ech.size + 4)
        val innerLen = 1 + 3 + 2 + 32 + 1 + 3 + 1 + 1 + 2 + extsLen
        val totalSize = 5 + innerLen
        
        val data = ByteArray(totalSize)
        val buf = ByteBuffer.wrap(data)
        buf.put(22.toByte()); buf.putShort(0x0303.toShort()); buf.putShort(innerLen.toShort())
        
        buf.put(1.toByte()) // Client Hello
        val hLen = innerLen - 4
        buf.put((hLen shr 16).toByte()); buf.put((hLen shr 8).toByte()); buf.put((hLen and 0xFF).toByte())
        buf.putShort(0x0303.toShort())
        val rnd32 = ByteArray(32); rnd.nextBytes(rnd32); buf.put(rnd32)
        buf.put(0.toByte()) // SID len
        buf.putShort(2.toShort()); buf.putShort(0x1301.toShort()) // Ciphers
        buf.put(1.toByte()); buf.put(0.toByte()) // Compression
        
        buf.putShort(extsLen.toShort())
        
        // SNI Header
        buf.putShort(0x0000.toShort())
        buf.putShort(sni.size.toShort())
        buf.put(sni)
        
        // ECH Header
        buf.putShort(0xfe0d.toShort()); buf.putShort(ech.size.toShort()); buf.put(ech)
        
        return data
    }

    fun buildFakeTcpRst(): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val noise = rnd.nextInt(2, 10)
        val data = ByteArray(6 + noise)
        data[0] = 0x52; data[1] = 0x53; data[2] = 0x54; data[3] = 0x00; data[4] = 0x00; data[5] = 0x00
        val rndBytes = ByteArray(noise); rnd.nextBytes(rndBytes); System.arraycopy(rndBytes, 0, data, 6, noise)
        return data
    }

    fun buildQuicInitial(): ByteArray {
        return buildUdpNoise(1200).apply {
            this[0] = 0xC3.toByte()
            val buf = ByteBuffer.wrap(this)
            buf.position(1)
            buf.putInt(0x00000001)
        }
    }

    fun buildStunBindingRequest(): ByteArray {
        val data = ByteArray(20)
        val buf = ByteBuffer.wrap(data)
        buf.putShort(0x0001.toShort()) // Binding Request
        buf.putShort(0.toShort()) // Length
        buf.putInt(0x2112A442) // Magic Cookie
        val tid = ByteArray(12); ThreadLocalRandom.current().nextBytes(tid); buf.put(tid)
        return data
    }

    fun buildFakeDtlsClientHello(): ByteArray {
        val data = buildUdpNoise(100)
        data[0] = 22.toByte() // Handshake
        data[1] = 254.toByte(); data[2] = 253.toByte() // DTLS 1.2
        return data
    }

    fun buildWireGuardHandshake(): ByteArray = buildWireguardFake()

    fun buildIkeHandshake(): ByteArray {
        val data = ByteArray(28)
        val buf = ByteBuffer.wrap(data)
        buf.putLong(ThreadLocalRandom.current().nextLong()) // Initiator SPI
        buf.putLong(0) // Responder SPI
        buf.put(33.toByte()) // Next Payload: Security Association
        buf.put(0x20.toByte()) // Version 2.0
        buf.put(34.toByte()) // Exchange Type: IKE_SA_INIT
        buf.put(0x08.toByte()) // Flags
        buf.putInt(0) // Message ID
        buf.putInt(28) // Length
        return data
    }

    fun buildDhcpRequest(): ByteArray {
        val data = ByteArray(300)
        data[0] = 1.toByte() // Boot Request
        data[1] = 1.toByte() // Ethernet
        data[2] = 6.toByte() // Hardware Address Length
        val buf = ByteBuffer.wrap(data)
        buf.position(4)
        buf.putInt(ThreadLocalRandom.current().nextInt()) // Transaction ID
        return data
    }

    fun buildSshHandshake(): ByteArray = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n".toByteArray()

    fun buildFakeHttpRequest(host: String): ByteArray = "GET / HTTP/1.1\r\nHost: $host\r\nUser-Agent: curl/7.81.0\r\nAccept: */*\r\n\r\n".toByteArray()

    fun buildRealisticTlsHello(host: String): ByteArray {
        val base = buildFakeClientHello(host, 32)
        return injectExtension(base, base.size, 0x0017, buildUdpNoise(16)) // Extended Master Secret
    }

    fun buildFakeClientHello(host: String, sidLen: Int): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val sni = buildSniExtension(host)
        val otherExtsLen = 6 + 6 + 6 // Signature (6) + Groups (6) + Versions (6)
        val extsLen = (sni.size + 4) + otherExtsLen
        val innerLen = 1 + 3 + 2 + 32 + 1 + sidLen + 2 + 2 + 1 + 1 + 2 + extsLen
        val totalSize = 5 + innerLen
        
        val data = ByteArray(totalSize)
        val buf = ByteBuffer.wrap(data)
        buf.put(22.toByte()); buf.putShort(0x0303.toShort()); buf.putShort(innerLen.toShort())
        buf.put(1.toByte())
        val hLen = innerLen - 4
        buf.put((hLen shr 16).toByte()); buf.put((hLen shr 8).toByte()); buf.put((hLen and 0xFF).toByte())
        buf.putShort(0x0303.toShort())
        val rnd32 = ByteArray(32); rnd.nextBytes(rnd32); buf.put(rnd32)
        buf.put(sidLen.toByte())
        if (sidLen > 0) { val sid = ByteArray(sidLen); rnd.nextBytes(sid); buf.put(sid) }
        
        buf.putShort(2.toShort()); buf.putShort(0x1301.toShort())
        buf.put(1.toByte()); buf.put(0.toByte())
        
        buf.putShort(extsLen.toShort())
        
        // SNI Header (Manual)
        buf.putShort(0x0000.toShort())
        buf.putShort(sni.size.toShort())
        buf.put(sni)
        
        // Add some common extensions
        buf.putShort(0x000d.toShort()); buf.putShort(2.toShort()); buf.putShort(0x0403.toShort()) // Signature Algorithms
        buf.putShort(0x000a.toShort()); buf.putShort(2.toShort()); buf.putShort(0x001d.toShort()) // Supported Groups
        buf.putShort(0x002b.toShort()); buf.putShort(2.toShort()); buf.putShort(0x0304.toShort()) // Supported Versions (TLS 1.3)
        
        return data
    }
    
    fun buildQuicVersionNegotiation(dcid: ByteArray = ByteArray(0), scid: ByteArray = ByteArray(0)): ByteArray {
        val data = ByteArray(13 + dcid.size + scid.size)
        data[0] = 0x80.toByte()
        val buf = ByteBuffer.wrap(data)
        buf.position(1)
        buf.putInt(0) // Version 0 for Negotiation
        buf.put(dcid.size.toByte()); buf.put(dcid)
        buf.put(scid.size.toByte()); buf.put(scid)
        buf.putInt(0x00000001) // Supported Version 1
        return data
    }

    fun buildDnsFakeQuery(host: String): ByteArray {
        val data = ByteArray(512)
        val buf = ByteBuffer.wrap(data)
        buf.putShort(ThreadLocalRandom.current().nextInt().toShort()) // Transaction ID
        buf.putShort(0x0100.toShort()) // Standard Query
        buf.putShort(1.toShort()) // Questions
        buf.putShort(0.toShort()); buf.putShort(0.toShort()); buf.putShort(0.toShort())
        
        val parts = host.split(".")
        for (part in parts) {
            buf.put(part.length.toByte())
            buf.put(part.toByteArray())
        }
        buf.put(0.toByte()) // End of QNAME
        buf.putShort(1.toShort()) // Type A
        buf.putShort(1.toShort()) // Class IN
        
        return data.copyOf(buf.position())
    }

    fun buildHttpChaosPacket(): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val methods = listOf("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "CONNECT")
        val paths = listOf("/", "/index.html", "/api/v1/status", "/login", "/wp-login.php", "/.env", "/config")
        val hosts = listOf("google.com", "blocked.com", "t.me", "twitter.com", "facebook.com", "instagram.com")
        
        val sb = StringBuilder()
        sb.append(methods.random()).append(" ").append(paths.random()).append(" HTTP/1.1\r\n")
        sb.append("Host: ").append(hosts.random()).append("\r\n")
        if (rnd.nextBoolean()) sb.append("User-Agent: ").append(listOf("curl/7.81.0", "Mozilla/5.0", "Wget/1.21.2").random()).append("\r\n")
        if (rnd.nextBoolean()) sb.append("Accept: */*\r\n")
        sb.append("\r\n")
        return sb.toString().toByteArray()
    }

    fun mangleHttpMethodCase(data: ByteArray, length: Int): ByteArray {
        val copy = data.copyOfRange(0, length)
        if (length > 4) {
            val rnd = ThreadLocalRandom.current()
            for (i in 0 until 4) {
                if (copy[i] >= 'A'.code.toByte() && copy[i] <= 'Z'.code.toByte() && rnd.nextBoolean()) {
                    copy[i] = (copy[i] + 32).toByte()
                }
            }
        }
        return copy
    }

    fun randomizeHeaderCase(data: ByteArray, length: Int): ByteArray {
        val copy = data.copyOfRange(0, length)
        val rnd = ThreadLocalRandom.current()
        for (i in 0 until length - 1) {
            if (copy[i] >= 'A'.code.toByte() && copy[i] <= 'Z'.code.toByte() && rnd.nextBoolean()) {
                copy[i] = (copy[i] + 32).toByte()
            } else if (copy[i] >= 'a'.code.toByte() && copy[i] <= 'z'.code.toByte() && rnd.nextBoolean()) {
                copy[i] = (copy[i] - 32).toByte()
            }
        }
        return copy
    }

    fun addSpaceToHttpMethod(data: ByteArray, length: Int): ByteArray {
        val firstSpace = data.indexOf(' '.code.toByte())
        if (firstSpace != -1 && firstSpace < length) {
            val res = ByteArray(length + 1)
            System.arraycopy(data, 0, res, 0, firstSpace)
            res[firstSpace] = ' '.code.toByte()
            System.arraycopy(data, firstSpace, res, firstSpace + 1, length - firstSpace)
            return res
        }
        return data.copyOf(length)
    }

    fun addDotToHost(data: ByteArray, length: Int): ByteArray {
        val s = String(data, 0, length, StandardCharsets.US_ASCII)
        val hostIdx = s.indexOf("Host:", ignoreCase = true)
        if (hostIdx != -1) {
            val lineEnd = s.indexOf("\r\n", hostIdx)
            if (lineEnd != -1) {
                val res = ByteArray(length + 1)
                System.arraycopy(data, 0, res, 0, lineEnd)
                res[lineEnd] = '.'.code.toByte()
                System.arraycopy(data, lineEnd, res, lineEnd + 1, length - lineEnd)
                return res
            }
        }
        return data.copyOf(length)
    }
    
    fun buildQuicInitialFake(): ByteArray = buildQuicInitial()

    fun getRandomUserAgent(): String {
        val agents = listOf(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
        )
        return agents.random()
    }

    fun mangleHttpMethod(data: ByteArray, length: Int): ByteArray = mangleHttpMethodCase(data, length)

    fun injectMultiTlsPadding(data: ByteArray, length: Int, count: Int): ByteArray {
        var current = data.copyOf(length)
        repeat(count) {
            current = injectTlsPadding(current, current.size, ThreadLocalRandom.current().nextInt(16, 64))
        }
        return current
    }

    fun shuffleTlsExtensions(data: ByteArray, length: Int): ByteArray {
        // Implementation for shuffling TLS extensions (simplified: returns copy for now if too complex to implement correctly without full parser)
        return data.copyOf(length)
    }

    fun addTlsGreaseExtensions(data: ByteArray, length: Int): ByteArray = injectGrease(data, length)

    fun moveSniExtensionToEnd(data: ByteArray, length: Int): ByteArray {
        // Implementation for moving SNI to end (simplified)
        return data.copyOf(length)
    }

    fun injectTlsGrease(data: ByteArray, length: Int): ByteArray = injectGrease(data, length)

    fun buildFakeEchExtension(): ByteArray = buildUdpNoise(ThreadLocalRandom.current().nextInt(128, 256))

    fun buildProtocolConfusion(type: String): ByteArray {
        return when(type.uppercase()) {
            "SSH" -> buildSshHandshake()
            "STUN" -> buildStunBindingRequest()
            "HTTP" -> buildFakeHttpRequest("google.com")
            "REDIS" -> "*1\r\n\$4\r\nPING\r\n".toByteArray()
            "MEMCACHED" -> "stats\r\n".toByteArray()
            "QUIC" -> buildQuicInitial()
            "DTLS" -> buildFakeDtlsClientHello()
            else -> buildUdpNoise(32)
        }
    }

    fun buildQuicJitterPad(size: Int): ByteArray = buildUdpNoise(size)

    fun buildQuicCryptoFake(): ByteArray {
        val data = buildUdpNoise(200)
        data[0] = 0x06 // CRYPTO frame type
        return data
    }

    fun buildTlsChaosPacket(): ByteArray = buildRealisticTlsHello("blocked.com")

    fun buildQuicRetry(dcid: ByteArray = ByteArray(0), scid: ByteArray = ByteArray(0), token: ByteArray = ByteArray(0)): ByteArray {
        val totalSize = 1 + 4 + 1 + dcid.size + 1 + scid.size + token.size + 16
        val data = ByteArray(totalSize)
        val buf = ByteBuffer.wrap(data)
        buf.put((0xC0 or (ThreadLocalRandom.current().nextInt(4) shl 4) or 3).toByte())
        buf.putInt(0x00000001)
        buf.put(dcid.size.toByte()); buf.put(dcid)
        buf.put(scid.size.toByte()); buf.put(scid)
        buf.put(token)
        val tag = ByteArray(16)
        ThreadLocalRandom.current().nextBytes(tag)
        buf.put(tag)
        return data
    }

    fun buildQuicVersionChaos(): ByteArray = buildQuicVersionNegotiation()

    fun injectTlsPadding(data: ByteArray, length: Int, padSize: Int): ByteArray {
        val padding = buildUdpNoise(padSize)
        return injectExtension(data, length, 0x0015, padding)
    }

    fun buildTelegramFake(): ByteArray {
        val bytes = ByteArray(64)
        java.util.concurrent.ThreadLocalRandom.current().nextBytes(bytes)
        bytes[56] = 0xef.toByte()
        return bytes
    }

    fun buildDiscordFake(): ByteArray {
        val bytes = ByteArray(120)
        java.util.concurrent.ThreadLocalRandom.current().nextBytes(bytes)
        bytes[0] = 0x80.toByte()
        bytes[1] = 0x78.toByte()
        return bytes
    }
}
