package com.aistudio.pinkproxy.fresh

object TlsParser {
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
                } else if (extType == 0xfe0d) {
                    // ECH (Encrypted Client Hello) detected! 
                    // We mark this but continue searching just in case SNI is also present (Outer CH)
                }
                pos += extLen
            }
        } catch (e: Exception) {
            // Ignore structured parsing error and try brute force search
        }
        
        return -1
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
                if (extType == 0xfe0d) return true
                pos += 4 + extLen
            }
        } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
        return false
    }
}
