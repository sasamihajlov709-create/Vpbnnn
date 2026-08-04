package com.aistudio.pinkproxy.fresh

object TlsParser {
    fun isClientHello(buffer: ByteArray, length: Int): Boolean {
        if (length < 44) return false
        return buffer[0] == 0x16.toByte() && buffer[5] == 0x01.toByte()
    }

    /**
     * Parses a TLS ClientHello packet and finds the exact offset of the SNI hostname string.
     * Returns the offset of the first character of the hostname, or -1 if not found.
     */
    fun findSniOffset(buffer: ByteArray, length: Int, host: String? = null): Int {
        if (length < 44) return -1
        
        // Ensure it's a TLS Handshake (0x16) and ClientHello (0x01)
        if (buffer[0] != 0x16.toByte()) return -1
        if (buffer[5] != 0x01.toByte()) return -1
        
        try {
            // Record layer version: 3.x
            if (buffer[1] != 0x03.toByte()) return -1

            // Session ID length (variable)
            val sessionIdLen = buffer[43].toInt() and 0xFF
            var pos = 44 + sessionIdLen
            
            // Cipher suites length (variable)
            if (pos + 1 >= length) return -1
            val cipherSuitesLen = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
            pos += 2 + cipherSuitesLen
            
            // Compression methods length (variable)
            if (pos >= length) return -1
            pos += 1 + (buffer[pos].toInt() and 0xFF)
            
            // Extensions length
            if (pos + 1 >= length) return -1
            val extensionsLen = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
            pos += 2
            
            val extEnd = minOf(pos + extensionsLen, length)
            
            while (pos + 3 < extEnd) {
                val extType = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
                val extLen = ((buffer[pos + 2].toInt() and 0xFF) shl 8) or (buffer[pos + 3].toInt() and 0xFF)
                
                pos += 4
                
                if (pos + extLen > extEnd) break // Bounds check

                if (extType == 0x0000) { // Server Name extension
                    // Check SNI list length
                    if (pos + 1 < extEnd) {
                        var sniPos = pos + 2
                        
                        // Look for HostName (Type 0)
                        while (sniPos + 2 < pos + extLen && sniPos + 2 < extEnd) {
                            val nameType = buffer[sniPos].toInt() and 0xFF
                            val nameLen = ((buffer[sniPos + 1].toInt() and 0xFF) shl 8) or (buffer[sniPos + 2].toInt() and 0xFF)
                            
                            if (sniPos + 3 + nameLen > extEnd) break // Bounds check

                            if (nameType == 0) { // HostName
                                return sniPos + 3
                            }
                            sniPos += 3 + nameLen
                        }
                    }
                } else if (extType == 0xfe0d || extType == 0xff0d || extType == 0x1102) {
                    // ECH (Encrypted Client Hello) or related extensions detected
                }
                pos += extLen
            }
        } catch (e: Throwable) {
            // Brute force search as last resort if structured parsing fails
            if (host != null && host.isNotEmpty()) {
                val offset = findHostInPayload(buffer, length, host)
                if (offset != -1) return offset
            }
        }
        
        return -1
    }

    fun extractHostname(buffer: ByteArray, length: Int, offset: Int): String? {
        if (offset < 3 || offset >= length) return null
        try {
            val nameLen = ((buffer[offset - 2].toInt() and 0xFF) shl 8) or (buffer[offset - 1].toInt() and 0xFF)
            if (offset + nameLen > length) return null
            return String(buffer, offset, nameLen, java.nio.charset.StandardCharsets.US_ASCII)
        } catch (e: Throwable) {
            return null
        }
    }

    fun isEchDetected(buffer: ByteArray, length: Int): Boolean {
        if (length < 44) return false
        if (buffer[0] != 0x16.toByte() || buffer[5] != 0x01.toByte()) return false
        
        try {
            val sessionIdLen = buffer[43].toInt() and 0xFF
            var pos = 44 + sessionIdLen
            if (pos + 1 >= length) return false
            val cipherSuitesLen = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
            pos += 2 + cipherSuitesLen
            if (pos >= length) return false
            pos += 1 + (buffer[pos].toInt() and 0xFF)
            if (pos + 1 >= length) return false
            val extensionsLen = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
            pos += 2
            val extEnd = minOf(pos + extensionsLen, length)
            
            while (pos + 3 < extEnd) {
                val extType = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
                val extLen = ((buffer[pos + 2].toInt() and 0xFF) shl 8) or (buffer[pos + 3].toInt() and 0xFF)
                if (extType == 0xfe0d || extType == 0xff0d || extType == 0x1102) return true
                pos += 4 + extLen
            }
        } catch (e: Throwable) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        return false
    }

    fun findHostInPayload(buffer: ByteArray, length: Int, host: String): Int {
        if (host.isEmpty()) return -1
        val hostBytes = host.toByteArray(java.nio.charset.StandardCharsets.US_ASCII)
        if (hostBytes.size > length) return -1
        
        for (i in 0..length - hostBytes.size) {
            var found = true
            for (j in hostBytes.indices) {
                if (buffer[i + j] != hostBytes[j]) {
                    found = false
                    break
                }
            }
            if (found) return i
        }
        return -1
    }

    fun getAlpn(buffer: ByteArray, length: Int): String? {
        if (length < 44) return null
        if (buffer[0] != 0x16.toByte() || buffer[5] != 0x01.toByte()) return null
        
        try {
            val sessionIdLen = buffer[43].toInt() and 0xFF
            var pos = 44 + sessionIdLen
            if (pos + 1 >= length) return null
            val cipherSuitesLen = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
            pos += 2 + cipherSuitesLen
            if (pos >= length) return null
            pos += 1 + (buffer[pos].toInt() and 0xFF)
            if (pos + 1 >= length) return null
            val extensionsLen = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
            pos += 2
            val extEnd = minOf(pos + extensionsLen, length)
            
            while (pos + 3 < extEnd) {
                val extType = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
                val extLen = ((buffer[pos + 2].toInt() and 0xFF) shl 8) or (buffer[pos + 3].toInt() and 0xFF)
                
                if (extType == 16) { // ALPN
                    if (pos + 6 < extEnd) {
                        val alpnListLen = ((buffer[pos + 4].toInt() and 0xFF) shl 8) or (buffer[pos + 5].toInt() and 0xFF)
                        val protoLen = buffer[pos + 6].toInt() and 0xFF
                        if (pos + 7 + protoLen <= extEnd) {
                            return String(buffer, pos + 7, protoLen, java.nio.charset.StandardCharsets.US_ASCII)
                        }
                    }
                }
                pos += 4 + extLen
            }
        } catch (e: Throwable) {}
        return null
    }

    fun getTlsRecordLength(buffer: ByteArray, offset: Int, length: Int): Int {
        if (length - offset < 5) return -1
        // TLS record types: 20 (ChangeCipherSpec), 21 (Alert), 22 (Handshake), 23 (ApplicationData)
        val type = buffer[offset].toInt() and 0xFF
        if (type < 20 || type > 23) return -1
        if (buffer[offset + 1].toInt() != 3) return -1 // Version major must be 3
        
        return (((buffer[offset + 3].toInt() and 0xFF) shl 8) or (buffer[offset + 4].toInt() and 0xFF)) + 5
    }

    /**
     * Injects a fake ECH extension (Grease) into ClientHello to bypass ECH-aware filters.
     */
    fun injectEchGrease(buffer: ByteArray, length: Int): ByteArray {
        if (!isClientHello(buffer, length)) return buffer.copyOf(length)
        
        try {
            val sessionIdLen = buffer[43].toInt() and 0xFF
            var pos = 44 + sessionIdLen
            val cipherSuitesLen = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
            pos += 2 + cipherSuitesLen
            pos += 1 + (buffer[pos].toInt() and 0xFF) // Compression
            
            // Extensions position
            val extLenPos = pos
            val extensionsLen = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
            pos += 2
            
            // Build Grease ECH extension: Type=0xfe0d (randomized), Length=random
            val rnd = java.util.concurrent.ThreadLocalRandom.current()
            val greaseType = if (rnd.nextBoolean()) 0xfe0d else 0xff0d
            val greaseLen = rnd.nextInt(16, 64)
            val greaseData = ByteArray(greaseLen)
            rnd.nextBytes(greaseData)
            
            val newExt = ByteArray(4 + greaseLen)
            newExt[0] = (greaseType shr 8).toByte()
            newExt[1] = (greaseType and 0xFF).toByte()
            newExt[2] = (greaseLen shr 8).toByte()
            newExt[3] = (greaseLen and 0xFF).toByte()
            System.arraycopy(greaseData, 0, newExt, 4, greaseLen)
            
            // Reconstruct the packet
            val newLen = length + newExt.size
            val result = ByteArray(newLen)
            System.arraycopy(buffer, 0, result, 0, pos) // Header + part of extensions
            System.arraycopy(newExt, 0, result, pos, newExt.size) // Inject grease at the start of extensions
            System.arraycopy(buffer, pos, result, pos + newExt.size, length - pos) // Rest
            
            // Update lengths
            val totalHandshakeLen = ((result[6].toInt() and 0xFF) shl 16) or ((result[7].toInt() and 0xFF) shl 8) or (result[8].toInt() and 0xFF)
            val newHandshakeLen = totalHandshakeLen + newExt.size
            result[6] = (newHandshakeLen shr 16).toByte()
            result[7] = (newHandshakeLen shr 8).toByte()
            result[8] = (newHandshakeLen and 0xFF).toByte()
            
            val recordLen = ((result[3].toInt() and 0xFF) shl 8) or (result[4].toInt() and 0xFF)
            val newRecordLen = recordLen + newExt.size
            result[3] = (newRecordLen shr 8).toByte()
            result[4] = (newRecordLen and 0xFF).toByte()
            
            val newExtensionsLen = extensionsLen + newExt.size
            result[extLenPos] = (newExtensionsLen shr 8).toByte()
            result[extLenPos + 1] = (newExtensionsLen and 0xFF).toByte()
            
            return result
        } catch (e: Throwable) {
            return buffer.copyOf(length)
        }
    }
}
