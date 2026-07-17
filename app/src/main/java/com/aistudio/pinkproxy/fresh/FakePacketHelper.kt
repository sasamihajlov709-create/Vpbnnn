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

    fun buildFakeClientHello(sni: String): ByteArray {
        val sniBytes = sni.toByteArray()
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)
        
        // 1. Build ClientHello Body
        val bodyBaos = ByteArrayOutputStream()
        val bodyDos = DataOutputStream(bodyBaos)
        
        bodyDos.writeShort(0x0303) // TLS 1.2
        val randomBytes = ByteArray(32)
        random.nextBytes(randomBytes)
        bodyDos.write(randomBytes) // Random
        
        bodyDos.writeByte(0x20) // Session ID length
        val sessionId = ByteArray(32)
        random.nextBytes(sessionId)
        bodyDos.write(sessionId)
        
        // Cipher Suites with deep shuffling
        val greaseValues = listOf(
            0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
            0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
        )
        val greaseCipher = greaseValues.random()
        val ciphers = mutableListOf<Short>()
        ciphers.add(greaseCipher.toShort())
        
        val tls13Ciphers = mutableListOf(
            0x1301.toShort(), // TLS_AES_128_GCM_SHA256
            0x1302.toShort(), // TLS_AES_256_GCM_SHA384
            0x1303.toShort()  // TLS_CHACHA20_POLY1305_SHA256
        )
        tls13Ciphers.shuffle()
        ciphers.addAll(tls13Ciphers)
        
        val tls12Ciphers = mutableListOf(
            0xc02b.toShort(), // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc02f.toShort(), // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xc02c.toShort(), // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc030.toShort(), // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xcca9.toShort(), // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0xcca8.toShort()  // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        )
        tls12Ciphers.shuffle()
        ciphers.addAll(tls12Ciphers)
        
        bodyDos.writeShort(ciphers.size * 2)
        ciphers.forEach { bodyDos.writeShort(it.toInt()) }
        
        bodyDos.writeByte(0x01) // Compression methods length
        bodyDos.writeByte(0x00) // Null compression
        
        // Build Individual Extensions
        val greaseVal1 = greaseValues.random()
        
        // GREASE Extension 1
        val greaseExt1 = buildExtension(greaseVal1, byteArrayOf())
        
        // SNI (Type 0)
        val sniDataBaos = ByteArrayOutputStream()
        val sniDataDos = DataOutputStream(sniDataBaos)
        sniDataDos.writeShort(sniBytes.size + 3)
        sniDataDos.writeByte(0x00) // HostName type
        sniDataDos.writeShort(sniBytes.size)
        sniDataDos.write(sniBytes)
        val sniExt = buildExtension(0x0000, sniDataBaos.toByteArray())
        
        // ALPN (Type 16)
        val alpnDataBaos = ByteArrayOutputStream()
        val alpnDataDos = DataOutputStream(alpnDataBaos)
        alpnDataDos.writeShort(0x000c) // ALPN list length
        alpnDataDos.writeByte(0x02) // "h2" len
        alpnDataDos.write("h2".toByteArray())
        alpnDataDos.writeByte(0x08) // "http/1.1" len
        alpnDataDos.write("http/1.1".toByteArray())
        val alpnExt = buildExtension(0x0010, alpnDataBaos.toByteArray())
        
        // Supported Groups (Type 10)
        val groupsDataBaos = ByteArrayOutputStream()
        val groupsDataDos = DataOutputStream(groupsDataBaos)
        groupsDataDos.writeShort(0x0008) // list length
        groupsDataDos.writeShort(greaseVal1) // GREASE
        groupsDataDos.writeShort(0x001d) // x25519
        groupsDataDos.writeShort(0x0017) // secp256r1
        groupsDataDos.writeShort(0x0018) // secp384r1
        val groupsExt = buildExtension(0x000a, groupsDataBaos.toByteArray())
        
        // EC Point Formats (Type 11)
        val ecPointExt = buildExtension(0x000b, byteArrayOf(0x01, 0x00))
        
        // Signature Algorithms (Type 13)
        val sigAlgDataBaos = ByteArrayOutputStream()
        val sigAlgDataDos = DataOutputStream(sigAlgDataBaos)
        sigAlgDataDos.writeShort(0x0010) // Signature algorithms list length
        val sigAlgs = mutableListOf(
            0x0403, // ecdsa_secp256r1_sha256
            0x0804, // rsa_pss_rsae_sha256
            0x0401, // rsa_pkcs1_sha256
            0x0503, // ecdsa_secp384r1_sha384
            0x0805, // rsa_pss_rsae_sha384
            0x0501, // rsa_pkcs1_sha384
            0x0806, // rsa_pss_rsae_sha512
            0x0601  // rsa_pkcs1_sha512
        )
        sigAlgs.shuffle()
        sigAlgs.forEach { sigAlgDataDos.writeShort(it) }
        val sigAlgExt = buildExtension(0x000d, sigAlgDataBaos.toByteArray())
        
        // Renegotiation Info (Type 65281)
        val renegExt = buildExtension(0xff01, byteArrayOf(0x00))
        
        // Supported Versions (Type 43)
        val versionsDataBaos = ByteArrayOutputStream()
        val versionsDataDos = DataOutputStream(versionsDataBaos)
        versionsDataDos.writeByte(0x06) // list length
        versionsDataDos.writeShort(greaseVal1) // GREASE in versions
        versionsDataDos.writeShort(0x0304) // TLS 1.3
        versionsDataDos.writeShort(0x0303) // TLS 1.2
        val versionsExt = buildExtension(0x002b, versionsDataBaos.toByteArray())
        
        // Key Share (Type 51)
        val keyShareDataBaos = ByteArrayOutputStream()
        val keyShareDataDos = DataOutputStream(keyShareDataBaos)
        keyShareDataDos.writeShort(0x0024) // Key shares length
        keyShareDataDos.writeShort(0x001d) // Group: x25519
        keyShareDataDos.writeShort(0x0020) // Key length 32
        val keyShare = ByteArray(32)
        random.nextBytes(keyShare)
        keyShareDataDos.write(keyShare)
        val keyShareExt = buildExtension(0x0033, keyShareDataBaos.toByteArray())
        
        // Shuffle the order of extensions to scramble JA3/JA4 fingerprints
        val extensionsList = mutableListOf(
            greaseExt1,
            sniExt,
            alpnExt,
            groupsExt,
            ecPointExt,
            sigAlgExt,
            renegExt,
            versionsExt,
            keyShareExt
        )
        extensionsList.shuffle()
        
        // Write extensions to extBaos
        val extBaos = ByteArrayOutputStream()
        val extDos = DataOutputStream(extBaos)
        extensionsList.forEach { extDos.write(it) }
        
        // Calculate needed padding to match browser payload size (prevent length analysis)
        val currentSize = bodyBaos.size() + extBaos.size() + 2 + 9 // +2 for extensions length field, +9 for record/handshake headers
        val targetSize = 512 + random.nextInt(128) // Randomized size between 512 and 640
        val paddingNeeded = targetSize - currentSize - 4 // -4 for padding extension type and length fields
        if (paddingNeeded > 0) {
            val paddingData = ByteArray(paddingNeeded)
            val paddingExt = buildExtension(0x0015, paddingData)
            extDos.write(paddingExt)
        }
        
        val extensions = extBaos.toByteArray()
        bodyDos.writeShort(extensions.size)
        bodyDos.write(extensions)
        
        val clientHello = bodyBaos.toByteArray()
        
        // 2. Build Record Header
        dos.writeByte(0x16) // Handshake type
        dos.writeShort(0x0301) // TLS 1.0 (legacy record version for compatibility)
        dos.writeShort(clientHello.size + 4)
        
        // 3. Build Handshake Header
        dos.writeByte(0x01) // ClientHello
        dos.writeByte(0x00)
        dos.writeShort(clientHello.size)
        dos.write(clientHello)
        
        return baos.toByteArray()
    }
}
