package com.aistudio.pinkproxy.fresh

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.util.Random

object FakePacketHelper {
    private var cachedQuicInitial = buildQuicInitial()
    private var cacheTime = System.currentTimeMillis()
    
    fun getCachedQuicInitial(): ByteArray {
        if (System.currentTimeMillis() - cacheTime > 30000) {
            cachedQuicInitial = buildQuicInitial()
            cacheTime = System.currentTimeMillis()
        }
        return cachedQuicInitial
    }
    fun buildExtension(type: Int, data: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)
        dos.writeShort(type)
        dos.writeShort(data.size)
        dos.write(data)
        return baos.toByteArray()
    }

    fun buildMultiSniHello(sni: String): ByteArray {
        val baos = ByteArrayOutputStream()
        
        
        // Handshake header (Client Hello)
        baos.write(0x16) // Content Type: Handshake
        baos.write(0x03) // Version: 3
        baos.write(0x01) // Version: 1 (TLS 1.0)
        
        val helloBaos = ByteArrayOutputStream()
        helloBaos.write(0x01) // Handshake Type: Client Hello
        helloBaos.write(0x00) // Length Placeholder
        helloBaos.write(0x00)
        helloBaos.write(0x00)
        
        helloBaos.write(0x03) // Version: 3
        helloBaos.write(0x03) // Version: 3 (TLS 1.2)
        
        // Random
        val randomBytes = ByteArray(32)
        java.util.concurrent.ThreadLocalRandom.current().nextBytes(randomBytes)
        helloBaos.write(randomBytes)
        
        // Session ID
        helloBaos.write(0x00)
        
        // Cipher Suites
        helloBaos.write(0x00)
        helloBaos.write(0x02)
        helloBaos.write(0xc0)
        helloBaos.write(0x2b)
        
        // Compression Methods
        helloBaos.write(0x01)
        helloBaos.write(0x00)
        
        // Extensions
        val extBaos = ByteArrayOutputStream()
        
        // SNI Extension 1 (Real)
        val sniBaos = ByteArrayOutputStream()
        sniBaos.write(0x00) // List length
        sniBaos.write(sni.length + 3)
        sniBaos.write(0x00) // Name type: host_name
        sniBaos.write(0x00) // Name length
        sniBaos.write(sni.length)
        sniBaos.write(sni.toByteArray())
        
        extBaos.write(0x00) // Extension Type: server_name
        extBaos.write(0x00)
        extBaos.write(0x00)
        extBaos.write(sniBaos.size())
        extBaos.write(sniBaos.toByteArray())
        
        // SNI Extension 2 (Fake/Grease)
        val fakeSni = "google.com"
        val fakeSniBaos = ByteArrayOutputStream()
        fakeSniBaos.write(0x00)
        fakeSniBaos.write(fakeSni.length + 3)
        fakeSniBaos.write(0x00)
        fakeSniBaos.write(0x00)
        fakeSniBaos.write(fakeSni.length)
        fakeSniBaos.write(fakeSni.toByteArray())
        
        extBaos.write(0x00) 
        extBaos.write(0x00)
        extBaos.write(0x00)
        extBaos.write(fakeSniBaos.size())
        extBaos.write(fakeSniBaos.toByteArray())
        
        val extData = extBaos.toByteArray()
        helloBaos.write(0x00) // Extensions length
        helloBaos.write(extData.size)
        helloBaos.write(extData)
        
        val helloData = helloBaos.toByteArray()
        val len = helloData.size - 4
        helloData[1] = ((len shr 16) and 0xFF).toByte()
        helloData[2] = ((len shr 8) and 0xFF).toByte()
        helloData[3] = (len and 0xFF).toByte()
        
        baos.write(0x00) // Handshake record length placeholder
        baos.write(helloData.size)
        baos.write(helloData)
        
        val fullData = baos.toByteArray()
        val recordLen = fullData.size - 5
        fullData[3] = ((recordLen shr 8) and 0xFF).toByte()
        fullData[4] = (recordLen and 0xFF).toByte()
        
        return fullData
    }

    fun buildPaddingExtension(size: Int): ByteArray {
        val padding = ByteArray(size.coerceAtLeast(0))
        java.util.concurrent.ThreadLocalRandom.current().nextBytes(padding)
        return buildExtension(0x0015, padding) // Type 21: Padding
    }

    fun buildFakeHttpRequest(host: String, path: String = "/"): ByteArray {
        val userAgents = listOf(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
        )
        val sb = StringBuilder()
        sb.append("GET $path HTTP/1.1\r\n")
        sb.append("Host: $host\r\n")
        sb.append("User-Agent: ${userAgents.random()}\r\n")
        sb.append("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n")
        sb.append("Accept-Language: en-US,en;q=0.5\r\n")
        sb.append("Accept-Encoding: gzip, deflate, br\r\n")
        sb.append("Connection: keep-alive\r\n")
        sb.append("Upgrade-Insecure-Requests: 1\r\n")
        sb.append("Sec-Fetch-Dest: document\r\n")
        sb.append("Sec-Fetch-Mode: navigate\r\n")
        sb.append("Sec-Fetch-Site: none\r\n")
        sb.append("Sec-Fetch-User: ?1\r\n")
        sb.append("Priority: u=1\r\n")
        sb.append("\r\n")
        return sb.toString().toByteArray()
    }

    fun mangleSni(sni: String): String {
        return when (java.util.concurrent.ThreadLocalRandom.current().nextInt(0, 2 + 1)) {
            0 -> sni.lowercase(java.util.Locale.ROOT) // Normalized lowercase
            1 -> {
                // Randomly change case of one letter
                val chars = sni.toCharArray()
                val idx = chars.indices.random()
                if (chars[idx].isLetter()) {
                    chars[idx] = if (chars[idx].isLowerCase()) chars[idx].uppercaseChar() else chars[idx].lowercaseChar()
                }
                String(chars)
            }
            2 -> if (sni.endsWith(".")) sni else "$sni." // Trailing dot (FQDN style)
            else -> sni
        }
    }

    fun buildFakeClientHello(sni: String, intensity: Int = 50, paddingSize: Int = 0, noMangle: Boolean = false): ByteArray {
        val mangledSni = if (intensity > 30 && !noMangle) mangleSni(sni) else sni
        val isChrome = java.util.concurrent.ThreadLocalRandom.current().nextBoolean()
        val sniBytes = mangledSni.toByteArray()
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)
        
        val bodyBaos = ByteArrayOutputStream()
        val bodyDos = DataOutputStream(bodyBaos)
        
        bodyDos.writeShort(0x0303) // TLS 1.2
        val randomBytes = ByteArray(32)
        java.util.concurrent.ThreadLocalRandom.current().nextBytes(randomBytes)
        bodyDos.write(randomBytes)
        
        bodyDos.writeByte(0x20)
        val sessionId = ByteArray(32)
        java.util.concurrent.ThreadLocalRandom.current().nextBytes(sessionId)
        bodyDos.write(sessionId)
        
        val greaseValues = listOf(
            0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
            0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
        )
        val greaseCipher = greaseValues.random()
        val ciphers = mutableListOf<Short>()
        
        if (isChrome) {
            ciphers.add(greaseCipher.toShort())
            ciphers.add(0x1301.toShort()) // TLS_AES_128_GCM_SHA256
            ciphers.add(0x1302.toShort()) // TLS_AES_256_GCM_SHA384
            ciphers.add(0x1303.toShort()) // TLS_CHACHA20_POLY1305_SHA256
            ciphers.add(0xc02b.toShort()) // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            ciphers.add(0xc02f.toShort()) // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            ciphers.add(0xc02c.toShort()) // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            ciphers.add(0xc030.toShort()) // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            ciphers.add(0xcca9.toShort()) // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            ciphers.add(0xcca8.toShort()) // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            ciphers.add(0xc013.toShort()) // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            ciphers.add(0xc014.toShort()) // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            ciphers.add(0x009c.toShort()) // TLS_RSA_WITH_AES_128_GCM_SHA256
            ciphers.add(0x009d.toShort()) // TLS_RSA_WITH_AES_256_GCM_SHA384
            ciphers.add(0x002f.toShort()) // TLS_RSA_WITH_AES_128_CBC_SHA
            ciphers.add(0x0035.toShort()) // TLS_RSA_WITH_AES_256_CBC_SHA
            ciphers.add(0x000a.toShort()) // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        } else {
            ciphers.add(0x1301.toShort())
            ciphers.add(0x1302.toShort())
            ciphers.add(0x1303.toShort())
            ciphers.add(0xc02b.toShort())
            ciphers.add(0xc02f.toShort())
            ciphers.add(0xcca9.toShort())
            ciphers.add(0xcca8.toShort())
            ciphers.add(0xc02c.toShort())
            ciphers.add(0xc030.toShort())
            ciphers.add(0xc009.toShort())
            ciphers.add(0xc00a.toShort())
            ciphers.add(0x002f.toShort())
            ciphers.add(0x0035.toShort())
            ciphers.add(0x000a.toShort())
        }
        
        bodyDos.writeShort(ciphers.size * 2)
        ciphers.forEach { bodyDos.writeShort(it.toInt()) }
        
        bodyDos.writeByte(0x01) // Compression Methods Length
        bodyDos.writeByte(0x00) // Null Compression
        
        val greaseVal1 = greaseValues.random()
        val greaseVal2 = greaseValues.filter { it != greaseVal1 }.random()
        val greaseExt1 = buildExtension(greaseVal1, byteArrayOf())
        
        // ECH (Encrypted Client Hello) Outer extension for better masking
        val echLen = 64 + java.util.concurrent.ThreadLocalRandom.current().nextInt(128)
        val echBytes = ByteArray(echLen)
        java.util.concurrent.ThreadLocalRandom.current().nextBytes(echBytes)
        val echExt = buildExtension(0xfe0d, echBytes)
        
        val sniDataBaos = ByteArrayOutputStream()
        val sniDataDos = DataOutputStream(sniDataBaos)
        sniDataDos.writeShort(sniBytes.size + 3)
        sniDataDos.writeByte(0x00) // Hostname type
        sniDataDos.writeShort(sniBytes.size)
        sniDataDos.write(sniBytes)
        val sniExt = buildExtension(0x0000, sniDataBaos.toByteArray())

        val alpnDataBaos = ByteArrayOutputStream()
        val alpnDataDos = DataOutputStream(alpnDataBaos)
        val protocols = if (isChrome) listOf("h2", "http/1.1") else listOf("h3", "h2", "http/1.1")
        alpnDataDos.writeShort(protocols.sumOf { it.length + 1 })
        protocols.forEach { proto ->
            val pBytes = proto.toByteArray()
            alpnDataDos.writeByte(pBytes.size)
            alpnDataDos.write(pBytes)
        }
        val alpnExt = buildExtension(0x0010, alpnDataBaos.toByteArray())

        val groupsDataBaos = ByteArrayOutputStream()
        val groupsDataDos = DataOutputStream(groupsDataBaos)
        val groups = if (isChrome) {
            listOf(greaseVal2, 0x001d, 0x0017, 0x0018)
        } else {
            listOf(0x001d, 0x0017, 0x0018, 0x0019)
        }
        groupsDataDos.writeShort(groups.size * 2)
        groups.forEach { groupsDataDos.writeShort(it) }
        val groupsExt = buildExtension(0x000a, groupsDataBaos.toByteArray())
        
        val ecPointExt = buildExtension(0x000b, byteArrayOf(0x01, 0x00))
        
        val sigAlgDataBaos = ByteArrayOutputStream()
        val sigAlgDataDos = DataOutputStream(sigAlgDataBaos)
        val sigAlgs = listOf(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201)
        sigAlgDataDos.writeShort(sigAlgs.size * 2)
        sigAlgs.forEach { sigAlgDataDos.writeShort(it) }
        val sigAlgExt = buildExtension(0x000d, sigAlgDataBaos.toByteArray())
        
        val versionsDataBaos = ByteArrayOutputStream()
        val versionsDataDos = DataOutputStream(versionsDataBaos)
        val versions = if (isChrome) listOf(greaseVal2, 0x0304, 0x0303) else listOf(0x0304, 0x0303)
        versionsDataDos.writeByte(versions.size * 2)
        versions.forEach { versionsDataDos.writeShort(it) }
        val versionsExt = buildExtension(0x002b, versionsDataBaos.toByteArray())
        
        val keyShareDataBaos = ByteArrayOutputStream()
        val keyShareDataDos = DataOutputStream(keyShareDataBaos)
        val keyShares = if (isChrome) listOf(greaseVal2, 0x001d) else listOf(0x001d)
        
        var ksTotalLen = 0
        keyShares.forEach { ks -> ksTotalLen += 4 + if (ks > 0x7000) 1 else 32 }
        keyShareDataDos.writeShort(ksTotalLen)
        
        keyShares.forEach { ks ->
            keyShareDataDos.writeShort(ks)
            val len = if (ks > 0x7000) 1 else 32
            keyShareDataDos.writeShort(len)
            val share = ByteArray(len); java.util.concurrent.ThreadLocalRandom.current().nextBytes(share); keyShareDataDos.write(share)
        }
        val keyShareExt = buildExtension(0x0033, keyShareDataBaos.toByteArray())
        
        val pskModesExt = buildExtension(0x002d, byteArrayOf(0x01, 0x01))
        
        // Advanced Chrome extensions
        val alpsExt = if (isChrome) buildExtension(0x4469, byteArrayOf(0x00, 0x02, 'h'.code.toByte(), '2'.code.toByte())) else null
        val compressCertExt = buildExtension(0x001b, byteArrayOf(0x02, 0x00, 0x02))
        val statusRequestExt = buildExtension(0x0005, byteArrayOf(0x01, 0x00, 0x00, 0x00, 0x00))
        
        // TLS 1.3 PSK (Pre-Shared Key) extension for session resumption simulation
        val pskLen = 32 + java.util.concurrent.ThreadLocalRandom.current().nextInt(32)
        val pskBytes = ByteArray(pskLen)
        java.util.concurrent.ThreadLocalRandom.current().nextBytes(pskBytes)
        val pskExt = buildExtension(0x0029, pskBytes)
        
        // TLS GREASE extensions
        val greaseExtReal = buildExtension(greaseValues.random(), ByteArray(java.util.concurrent.ThreadLocalRandom.current().nextInt(5)))

        val extensionsList = mutableListOf(sniExt, alpnExt, groupsExt, ecPointExt, sigAlgExt, versionsExt, keyShareExt, pskModesExt, compressCertExt, statusRequestExt, echExt, pskExt, greaseExtReal)
        if (isChrome) {
            extensionsList.add(0, greaseExt1)
            alpsExt?.let { extensionsList.add(it) }
            extensionsList.shuffle()
        }
        
        val extBaos = ByteArrayOutputStream()
        extensionsList.forEach { extBaos.write(it) }
        
        val currentSize = bodyBaos.size() + extBaos.size() + 2 + 9
        val targetSize = (1200 + (intensity * 2) + java.util.concurrent.ThreadLocalRandom.current().nextInt(300)).coerceAtLeast(currentSize + paddingSize + 4)
        val paddingNeeded = targetSize - currentSize - 4
        if (paddingNeeded > 0) {
            extBaos.write(buildExtension(0x0015, ByteArray(paddingNeeded)))
        }
        
        bodyDos.writeShort(extBaos.size())
        bodyDos.write(extBaos.toByteArray())
        
        val clientHello = bodyBaos.toByteArray()
        dos.writeByte(0x16); dos.writeShort(0x0301); dos.writeShort(clientHello.size + 4)
        dos.writeByte(0x01); dos.writeByte(0x00); dos.writeShort(clientHello.size); dos.write(clientHello)
        
        return baos.toByteArray()
    }

    fun buildFakeUdpPacket(size: Int): ByteArray {
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)
        
        when (java.util.concurrent.ThreadLocalRandom.current().nextInt(3)) {
            0 -> {
                dos.writeShort(0x0001)
                dos.writeShort((size - 20).coerceAtLeast(0))
                dos.writeInt(0x2112A442)
                val transactionId = ByteArray(12)
                java.util.concurrent.ThreadLocalRandom.current().nextBytes(transactionId)
                dos.write(transactionId)
            }
            1 -> {
                dos.writeByte(0x16)
                dos.writeShort(0xfeff)
                dos.writeShort(0)
                val sequence = ByteArray(6)
                java.util.concurrent.ThreadLocalRandom.current().nextBytes(sequence)
                dos.write(sequence)
                dos.writeShort((size - 13).coerceAtLeast(0))
                dos.writeByte(0x01)
            }
            else -> {
                val data = ByteArray(size.coerceAtMost(1200))
                java.util.concurrent.ThreadLocalRandom.current().nextBytes(data)
                dos.write(data)
            }
        }
        
        val current = baos.toByteArray()
        if (current.size < size) {
            val padding = ByteArray(size - current.size)
            java.util.concurrent.ThreadLocalRandom.current().nextBytes(padding)
            return current + padding
        }
        return current
    }

    fun buildFakeHttp2Frame(type: Int = 0): ByteArray {
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)
        val length = java.util.concurrent.ThreadLocalRandom.current().nextInt(16, 256 + 1)
        // Length (24 bits)
        dos.writeByte((length shr 16) and 0xFF)
        dos.writeByte((length shr 8) and 0xFF)
        dos.writeByte(length and 0xFF)
        dos.writeByte(type) // Type
        dos.writeByte(if (java.util.concurrent.ThreadLocalRandom.current().nextBoolean()) 0x01 else 0x00) // Flags
        dos.writeInt(java.util.concurrent.ThreadLocalRandom.current().nextInt(0x7FFFFFFF)) // Stream ID (ignore first bit)
        val payload = ByteArray(length)
        java.util.concurrent.ThreadLocalRandom.current().nextBytes(payload)
        dos.write(payload)
        return baos.toByteArray()
    }

    fun buildEchPadding(size: Int = 128): ByteArray {
        val baos = ByteArrayOutputStream()
        // Simulate ECH outer extension padding to confuse DPI length analysis
        baos.write(0xfe) // Extension Type High (ECH is 0xfe08)
        baos.write(0x08) // Extension Type Low
        baos.write((size shr 8) and 0xFF)
        baos.write(size and 0xFF)
        val padding = ByteArray(size)
        java.util.concurrent.ThreadLocalRandom.current().nextBytes(padding)
        baos.write(padding)
        return baos.toByteArray()
    }

    fun buildTlsNoise(length: Int = 100): ByteArray {
        val baos = ByteArrayOutputStream()
        // Content Type: Handshake (22)
        baos.write(22)
        // Version: TLS 1.2 (0x0303)
        baos.write(0x03); baos.write(0x03)
        // Length
        baos.write((length shr 8) and 0xFF); baos.write(length and 0xFF)
        // Garbage Handshake Data
        val garbage = ByteArray(length)
        java.util.concurrent.ThreadLocalRandom.current().nextBytes(garbage)
        baos.write(garbage)
        return baos.toByteArray()
    }

    fun buildChromeHello(sni: String): ByteArray {
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)
        dos.writeByte(0x16)
        dos.writeShort(0x0301)
        val body = ByteArrayOutputStream()
        val bd = DataOutputStream(body)
        bd.writeByte(0x01)
        bd.write(byteArrayOf(0, 0, 0))
        bd.writeShort(0x0303)
        val random = ByteArray(32)
        java.util.concurrent.ThreadLocalRandom.current().nextBytes(random)
        bd.write(random)
        bd.writeByte(32)
        val sid = ByteArray(32)
        java.util.concurrent.ThreadLocalRandom.current().nextBytes(sid)
        bd.write(sid)
        val ciphers = byteArrayOf(
            0x13.toByte(), 0x01.toByte(), 0x13.toByte(), 0x02.toByte(), 0x13.toByte(), 0x03.toByte(),
            0xc0.toByte(), 0x2b.toByte(), 0xc0.toByte(), 0x2f.toByte(), 0xc0.toByte(), 0x2c.toByte(), 0xc0.toByte(), 0x30.toByte()
        )
        bd.writeShort(ciphers.size)
        bd.write(ciphers)
        bd.writeByte(1)
        bd.writeByte(0)
        val ext = ByteArrayOutputStream()
        val ed = DataOutputStream(ext)
        ed.writeShort(0x0000)
        val sniBaos = ByteArrayOutputStream()
        sniBaos.write(0x00); sniBaos.write(0x00); sniBaos.write((sni.length + 3) shr 8); sniBaos.write(sni.length + 3)
        sniBaos.write(0x00); sniBaos.write(sni.length shr 8); sniBaos.write(sni.length)
        sniBaos.write(sni.toByteArray())
        ed.writeShort(sniBaos.size())
        ed.write(sniBaos.toByteArray())
        val extData = ext.toByteArray()
        bd.writeShort(extData.size)
        bd.write(extData)
        val fullBody = body.toByteArray()
        val len = fullBody.size - 4
        fullBody[1] = ((len shr 16) and 0xFF).toByte()
        fullBody[2] = ((len shr 8) and 0xFF).toByte()
        fullBody[3] = (len and 0xFF).toByte()
        dos.writeShort(fullBody.size)
        dos.write(fullBody)
        return baos.toByteArray()
    }

    fun buildFirefoxHello(sni: String): ByteArray {
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)
        dos.writeByte(0x16)
        dos.writeShort(0x0301)
        val body = ByteArrayOutputStream()
        val bd = DataOutputStream(body)
        bd.writeByte(0x01)
        bd.write(byteArrayOf(0, 0, 0))
        bd.writeShort(0x0303)
        val random = ByteArray(32)
        java.util.concurrent.ThreadLocalRandom.current().nextBytes(random)
        bd.write(random)
        bd.writeByte(0) // Firefox often uses empty session ID in newer versions or specific configs
        val ciphers = byteArrayOf(
            0x13.toByte(), 0x01.toByte(), 0x13.toByte(), 0x02.toByte(), 0x13.toByte(), 0x03.toByte(),
            0xc0.toByte(), 0x2b.toByte(), 0xc0.toByte(), 0x2f.toByte(), 0xcc.toByte(), 0xa9.toByte(),
            0xcc.toByte(), 0xa8.toByte(), 0xc0.toByte(), 0xaf.toByte(), 0xc0.toByte(), 0xad.toByte()
        )
        bd.writeShort(ciphers.size)
        bd.write(ciphers)
        bd.writeByte(1)
        bd.writeByte(0)
        
        val ext = ByteArrayOutputStream()
        val ed = DataOutputStream(ext)
        
        // SNI
        ed.writeShort(0x0000)
        val sniBaos = ByteArrayOutputStream()
        sniBaos.write(0x00); sniBaos.write(0x00); sniBaos.write((sni.length + 3) shr 8); sniBaos.write(sni.length + 3)
        sniBaos.write(0x00); sniBaos.write(sni.length shr 8); sniBaos.write(sni.length)
        sniBaos.write(sni.toByteArray())
        ed.writeShort(sniBaos.size())
        ed.write(sniBaos.toByteArray())
        
        // Supported Versions (TLS 1.3)
        ed.writeShort(0x002b)
        ed.writeShort(3)
        ed.writeByte(2)
        ed.writeShort(0x0304)
        
        val extData = ext.toByteArray()
        bd.writeShort(extData.size)
        bd.write(extData)
        
        val fullBody = body.toByteArray()
        val len = fullBody.size - 4
        fullBody[1] = ((len shr 16) and 0xFF).toByte()
        fullBody[2] = ((len shr 8) and 0xFF).toByte()
        fullBody[3] = (len and 0xFF).toByte()
        dos.writeShort(fullBody.size)
        dos.write(fullBody)
        return baos.toByteArray()
    }

    fun buildTls13Hello(sni: String): ByteArray {
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)
        dos.writeByte(0x16)
        dos.writeShort(0x0303) // TLS 1.2 record version for compatibility
        
        val body = ByteArrayOutputStream()
        val bd = DataOutputStream(body)
        bd.writeByte(0x01)
        bd.write(byteArrayOf(0, 0, 0))
        bd.writeShort(0x0303)
        val random = ByteArray(32)
        java.util.concurrent.ThreadLocalRandom.current().nextBytes(random)
        bd.write(random)
        bd.writeByte(32)
        val sid = ByteArray(32)
        java.util.concurrent.ThreadLocalRandom.current().nextBytes(sid)
        bd.write(sid)
        
        // Only TLS 1.3 ciphers
        val ciphers = byteArrayOf(0x13, 0x01, 0x13, 0x02, 0x13, 0x03)
        bd.writeShort(ciphers.size)
        bd.write(ciphers)
        bd.writeByte(1)
        bd.writeByte(0)
        
        val ext = ByteArrayOutputStream()
        val ed = DataOutputStream(ext)
        
        // SNI
        ed.writeShort(0x0000)
        val sniBaos = ByteArrayOutputStream()
        sniBaos.write(0x00); sniBaos.write(0x00); sniBaos.write((sni.length + 3) shr 8); sniBaos.write(sni.length + 3)
        sniBaos.write(0x00); sniBaos.write(sni.length shr 8); sniBaos.write(sni.length)
        sniBaos.write(sni.toByteArray())
        ed.writeShort(sniBaos.size())
        ed.write(sniBaos.toByteArray())
        
        // Supported Versions
        ed.writeShort(0x002b)
        ed.writeShort(3)
        ed.writeByte(2)
        ed.writeShort(0x0304)
        
        // Signature Algorithms
        ed.writeShort(0x000d)
        val sigs = byteArrayOf(0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06)
        ed.writeShort(sigs.size + 2)
        ed.writeShort(sigs.size)
        ed.write(sigs)
        
        val extData = ext.toByteArray()
        bd.writeShort(extData.size)
        bd.write(extData)
        
        val fullBody = body.toByteArray()
        val len = fullBody.size - 4
        fullBody[1] = ((len shr 16) and 0xFF).toByte()
        fullBody[2] = ((len shr 8) and 0xFF).toByte()
        fullBody[3] = (len and 0xFF).toByte()
        dos.writeShort(fullBody.size)
        dos.write(fullBody)
        return baos.toByteArray()
    }

    fun buildFakeSshHandshake(): ByteArray {
        val versions = listOf(
            "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3",
            "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
            "SSH-2.0-Putty_Release_0.81"
        )
        return "${versions.random()}\r\n".toByteArray()
    }

    fun buildFakeWebSocketHandshake(host: String): ByteArray {
        val key = ByteArray(16)
        java.util.concurrent.ThreadLocalRandom.current().nextBytes(key)
        val base64Key = android.util.Base64.encodeToString(key, android.util.Base64.NO_WRAP)
        
        val sb = StringBuilder()
        sb.append("GET /chat HTTP/1.1\r\n")
        sb.append("Host: $host\r\n")
        sb.append("Upgrade: websocket\r\n")
        sb.append("Connection: Upgrade\r\n")
        sb.append("Sec-WebSocket-Key: $base64Key\r\n")
        sb.append("Sec-WebSocket-Protocol: chat, superchat\r\n")
        sb.append("Sec-WebSocket-Version: 13\r\n")
        sb.append("Origin: https://$host\r\n")
        sb.append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\r\n")
        sb.append("\r\n")
        return sb.toString().toByteArray()
    }

    fun buildQuicInitial(destConnId: ByteArray? = null): ByteArray {
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)
        dos.writeByte(0xC0) 
        dos.writeInt(0x00000001)
        val dcid = destConnId ?: ByteArray(8).apply { java.util.concurrent.ThreadLocalRandom.current().nextBytes(this) }
        dos.writeByte(dcid.size); dos.write(dcid)
        val scid = ByteArray(8).apply { java.util.concurrent.ThreadLocalRandom.current().nextBytes(this) }
        dos.writeByte(scid.size); dos.write(scid)
        dos.writeByte(0x00)
        val payloadLen = 1200
        dos.writeShort(0x4000 or (payloadLen and 0x3FFF))
        val packetNumber = ByteArray(4).apply { java.util.concurrent.ThreadLocalRandom.current().nextBytes(this) }
        dos.write(packetNumber)
        val payload = ByteArray(payloadLen - 4).apply { java.util.concurrent.ThreadLocalRandom.current().nextBytes(this) }
        payload[0] = 0x06; payload[1] = 0x00; payload[2] = 0x40; payload[3] = 0x01
        dos.write(payload)
        return baos.toByteArray()
    }
}
