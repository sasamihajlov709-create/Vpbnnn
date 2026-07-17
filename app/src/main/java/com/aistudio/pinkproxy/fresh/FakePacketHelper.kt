package com.aistudio.pinkproxy.fresh

object FakePacketHelper {
    fun buildFakeClientHello(sni: String): ByteArray {
        val sniBytes = sni.toByteArray()
        val baos = java.io.ByteArrayOutputStream()
        val dos = java.io.DataOutputStream(baos)
        
        // 1. Build ClientHello Body
        val bodyBaos = java.io.ByteArrayOutputStream()
        val bodyDos = java.io.DataOutputStream(bodyBaos)
        
        bodyDos.writeShort(0x0303) // TLS 1.2
        val random = ByteArray(32)
        java.util.Random().nextBytes(random)
        bodyDos.write(random) // Random
        bodyDos.writeByte(0x20) // Session ID length
        val sessionId = ByteArray(32)
        java.util.Random().nextBytes(sessionId)
        bodyDos.write(sessionId)
        
        // Cipher Suites
        val greaseCipher = listOf(0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a).random()
        val ciphers = mutableListOf<Short>()
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
        
        bodyDos.writeShort(ciphers.size * 2)
        ciphers.forEach { bodyDos.writeShort(it.toInt()) }
        
        bodyDos.writeByte(0x01) // Compression methods length
        bodyDos.writeByte(0x00) // Null
        
        // Extensions
        val extBaos = java.io.ByteArrayOutputStream()
        val extDos = java.io.DataOutputStream(extBaos)
        
        // GREASE Extension 1
        val greaseVal1 = listOf(0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a).random()
        extDos.writeShort(greaseVal1)
        extDos.writeShort(0x0000)

        // SNI
        extDos.writeShort(0x0000)
        extDos.writeShort(sniBytes.size + 5)
        extDos.writeShort(sniBytes.size + 3)
        extDos.writeByte(0x00)
        extDos.writeShort(sniBytes.size)
        extDos.write(sniBytes)
        
        // ALPN (Extension 16)
        extDos.writeShort(0x0010)
        extDos.writeShort(0x000e)
        extDos.writeShort(0x000c)
        extDos.writeByte(0x02)
        extDos.write("h2".toByteArray())
        extDos.writeByte(0x08)
        extDos.write("http/1.1".toByteArray())

        // Supported Groups (Extension 10)
        extDos.writeShort(0x000a)
        extDos.writeShort(0x000a)
        extDos.writeShort(0x0008)
        extDos.writeShort(greaseVal1) // GREASE in groups too
        extDos.writeShort(0x001d) // x25519
        extDos.writeShort(0x0017) // secp256r1
        extDos.writeShort(0x0018) // secp384r1
        
        // EC Point Formats (Extension 11)
        extDos.writeShort(0x000b)
        extDos.writeShort(0x0002)
        extDos.writeByte(0x01)
        extDos.writeByte(0x00) // uncompressed
        
        // Signature Algorithms (Extension 13)
        extDos.writeShort(0x000d)
        extDos.writeShort(0x0012)
        extDos.writeShort(0x0010)
        extDos.writeShort(0x0403) // ecdsa_secp256r1_sha256
        extDos.writeShort(0x0804) // rsa_pss_rsae_sha256
        extDos.writeShort(0x0401) // rsa_pkcs1_sha256
        extDos.writeShort(0x0503) // ecdsa_secp384r1_sha384
        extDos.writeShort(0x0805) // rsa_pss_rsae_sha384
        extDos.writeShort(0x0501) // rsa_pkcs1_sha384
        extDos.writeShort(0x0806) // rsa_pss_rsae_sha512
        extDos.writeShort(0x0601) // rsa_pkcs1_sha512
        
        // Renegotiation Info (Extension 65281)
        extDos.writeShort(0xff01)
        extDos.writeShort(0x0001)
        extDos.writeByte(0x00)

        // Supported Versions (Extension 43)
        extDos.writeShort(0x002b)
        extDos.writeShort(0x0007)
        extDos.writeByte(0x06)
        extDos.writeShort(greaseVal1) // GREASE in versions
        extDos.writeShort(0x0304) // TLS 1.3
        extDos.writeShort(0x0303) // TLS 1.2
        extDos.writeShort(0x0302) // TLS 1.1

        // Key Share (Extension 51)
        extDos.writeShort(0x0033)
        extDos.writeShort(0x0026)
        extDos.writeShort(0x0024)
        extDos.writeShort(0x001d) // x25519
        extDos.writeShort(0x0020) // 32 bytes
        val keyShare = ByteArray(32)
        java.util.Random().nextBytes(keyShare)
        extDos.write(keyShare)

        // Padding (Extension 21) - Crucial for mimicking modern browsers
        val currentSize = bodyBaos.size() + extBaos.size() + 2 + 5 // +2 for extensions length, +5 for record/handshake headers
        val targetSize = 512 + (java.util.Random().nextInt(128)) // Randomized common size
        val paddingNeeded = targetSize - currentSize - 4 // -4 for extension header
        if (paddingNeeded > 0) {
            extDos.writeShort(0x0015)
            extDos.writeShort(paddingNeeded)
            extDos.write(ByteArray(paddingNeeded))
        }
        
        val extensions = extBaos.toByteArray()
        bodyDos.writeShort(extensions.size)
        bodyDos.write(extensions)
        
        val clientHello = bodyBaos.toByteArray()
        
        // 2. Build Record Header
        dos.writeByte(0x16) // Handshake
        dos.writeShort(0x0301) // TLS 1.0 (legacy record version)
        dos.writeShort(clientHello.size + 4)
        
        // 3. Build Handshake Header
        dos.writeByte(0x01) // ClientHello
        dos.writeByte(0x00)
        dos.writeShort(clientHello.size)
        dos.write(clientHello)
        
        return baos.toByteArray()
    }
}
