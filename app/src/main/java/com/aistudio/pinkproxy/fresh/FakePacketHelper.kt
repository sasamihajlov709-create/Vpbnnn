package com.aistudio.pinkproxy.fresh

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.util.Random

object FakePacketHelper {
    private val random = Random()

    private fun buildExtension(type: Int, data: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)
        dos.writeShort(type)
        dos.writeShort(data.size)
        dos.write(data)
        return baos.toByteArray()
    }

    fun buildPaddingExtension(size: Int): ByteArray {
        val padding = ByteArray(size.coerceAtLeast(0))
        random.nextBytes(padding)
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

    fun buildFakeClientHello(sni: String, intensity: Int = 50, paddingSize: Int = 0): ByteArray {
        val isChrome = random.nextBoolean()
        val sniBytes = sni.toByteArray()
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)
        
        val bodyBaos = ByteArrayOutputStream()
        val bodyDos = DataOutputStream(bodyBaos)
        
        bodyDos.writeShort(0x0303) // TLS 1.2
        val randomBytes = ByteArray(32)
        random.nextBytes(randomBytes)
        bodyDos.write(randomBytes)
        
        bodyDos.writeByte(0x20)
        val sessionId = ByteArray(32)
        random.nextBytes(sessionId)
        bodyDos.write(sessionId)
        
        val greaseValues = listOf(
            0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
            0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
        )
        val greaseCipher = greaseValues.random()
        val ciphers = mutableListOf<Short>()
        
        if (isChrome) {
            ciphers.add(greaseCipher.toShort())
            ciphers.add(0x1301.toShort())
            ciphers.add(0x1302.toShort())
            ciphers.add(0x1303.toShort())
            ciphers.add(0xc02b.toShort())
            ciphers.add(0xc02f.toShort())
            ciphers.add(0xc02c.toShort())
            ciphers.add(0xc030.toShort())
            ciphers.add(0xcca9.toShort())
            ciphers.add(0xcca8.toShort())
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
        }
        
        bodyDos.writeShort(ciphers.size * 2)
        ciphers.forEach { bodyDos.writeShort(it.toInt()) }
        
        bodyDos.writeByte(0x01)
        bodyDos.writeByte(0x00)
        
        val greaseVal1 = greaseValues.random()
        val greaseExt1 = buildExtension(greaseVal1, byteArrayOf())
        
        val echLen = 64 + random.nextInt(64)
        val echBytes = ByteArray(echLen)
        random.nextBytes(echBytes)
        val echExt = buildExtension(0xfe0d, echBytes)
        
        val sniDataBaos = ByteArrayOutputStream()
        val sniDataDos = DataOutputStream(sniDataBaos)
        sniDataDos.writeShort(sniBytes.size + 3)
        sniDataDos.writeByte(0x00)
        sniDataDos.writeShort(sniBytes.size)
        sniDataDos.write(sniBytes)
        val sniExt = buildExtension(0x0000, sniDataBaos.toByteArray())

        val alpnDataBaos = ByteArrayOutputStream()
        val protocols = listOf("h2", "http/1.1")
        alpnDataBaos.write(protocols.sumOf { it.length + 1 })
        protocols.forEach { proto ->
            val pBytes = proto.toByteArray()
            alpnDataBaos.write(pBytes.size)
            alpnDataBaos.write(pBytes)
        }
        val alpnExt = buildExtension(0x0010, alpnDataBaos.toByteArray())

        val groupsDataBaos = ByteArrayOutputStream()
        val groupsDataDos = DataOutputStream(groupsDataBaos)
        val groups = if (isChrome) listOf(0x6399, 0x001d, 0x0017, 0x0018) else listOf(0x001d, 0x0017, 0x0018)
        groupsDataDos.writeShort(groups.size * 2)
        groups.forEach { groupsDataDos.writeShort(it) }
        val groupsExt = buildExtension(0x000a, groupsDataBaos.toByteArray())
        
        val ecPointExt = buildExtension(0x000b, byteArrayOf(0x01, 0x00))
        
        val sigAlgDataBaos = ByteArrayOutputStream()
        val sigAlgDataDos = DataOutputStream(sigAlgDataBaos)
        val sigAlgs = listOf(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)
        sigAlgDataDos.writeShort(sigAlgs.size * 2)
        sigAlgs.forEach { sigAlgDataDos.writeShort(it) }
        val sigAlgExt = buildExtension(0x000d, sigAlgDataBaos.toByteArray())
        
        val versionsDataBaos = ByteArrayOutputStream()
        val versionsDataDos = DataOutputStream(versionsDataBaos)
        val versions = if (isChrome) listOf(greaseVal1, 0x0304, 0x0303) else listOf(0x0304, 0x0303)
        versionsDataDos.writeByte(versions.size * 2)
        versions.forEach { versionsDataDos.writeShort(it) }
        val versionsExt = buildExtension(0x002b, versionsDataBaos.toByteArray())
        
        val keyShareDataBaos = ByteArrayOutputStream()
        val keyShareDataDos = DataOutputStream(keyShareDataBaos)
        val keyShares = if (isChrome) listOf(0x6399, 0x001d) else listOf(0x001d)
        
        var ksLen = 0
        keyShares.forEach { ks ->
            ksLen += 4 + if (ks == 0x6399) 1184 else 32
        }
        keyShareDataDos.writeShort(ksLen)
        
        keyShares.forEach { ks ->
            keyShareDataDos.writeShort(ks)
            val len = if (ks == 0x6399) 1184 else 32
            keyShareDataDos.writeShort(len)
            val share = ByteArray(len); random.nextBytes(share); keyShareDataDos.write(share)
        }
        val keyShareExt = buildExtension(0x0033, keyShareDataBaos.toByteArray())
        
        val pskModesExt = buildExtension(0x002d, byteArrayOf(0x01, 0x01))

        val extensionsList = if (isChrome) {
            mutableListOf(greaseExt1, echExt, sniExt, alpnExt, groupsExt, ecPointExt, sigAlgExt, buildExtension(0xff01, byteArrayOf(0x00)), versionsExt, keyShareExt, pskModesExt)
        } else {
            mutableListOf(sniExt, alpnExt, groupsExt, ecPointExt, sigAlgExt, versionsExt, keyShareExt, pskModesExt)
        }
        
        if (isChrome) extensionsList.shuffle()
        
        val extBaos = ByteArrayOutputStream()
        extensionsList.forEach { extBaos.write(it) }
        
        val currentSize = bodyBaos.size() + extBaos.size() + 2 + 9
        val targetSize = (1400 + (intensity * 3) + random.nextInt(400)).coerceAtLeast(currentSize + paddingSize + 4)
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
        
        when (random.nextInt(3)) {
            0 -> {
                dos.writeShort(0x0001)
                dos.writeShort(size.coerceAtMost(20) - 20)
                dos.writeInt(0x2112A442)
                val transactionId = ByteArray(12)
                random.nextBytes(transactionId)
                dos.write(transactionId)
            }
            1 -> {
                dos.writeByte(0x16)
                dos.writeShort(0xfeff)
                dos.writeShort(0)
                val sequence = ByteArray(6)
                random.nextBytes(sequence)
                dos.write(sequence)
                dos.writeShort(size.coerceAtMost(100) - 13)
                dos.writeByte(0x01)
            }
            else -> {
                val data = ByteArray(size.coerceAtMost(1200))
                random.nextBytes(data)
                dos.write(data)
            }
        }
        
        val current = baos.toByteArray()
        if (current.size < size) {
            val padding = ByteArray(size - current.size)
            random.nextBytes(padding)
            return current + padding
        }
        return current
    }
}
