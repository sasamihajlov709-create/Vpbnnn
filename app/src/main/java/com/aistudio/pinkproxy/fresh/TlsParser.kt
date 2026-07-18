package com.aistudio.pinkproxy.fresh

object TlsParser {
    /**
     * Parses a TLS ClientHello packet and finds the exact offset of the SNI hostname string.
     * Returns the offset of the first character of the hostname, or -1 if not found.
     */
    fun findSniOffset(buffer: ByteArray, length: Int): Int {
        if (length < 43) return -1
        
        // Ensure it's a TLS Handshake (0x16) and ClientHello (0x01)
        if (buffer[0] != 0x16.toByte()) return -1
        if (buffer[5] != 0x01.toByte()) return -1
        
        try {
            // Session ID length (variable)
            val sessionIdLen = buffer[43].toInt() and 0xFF
            var pos = 44 + sessionIdLen
            
            // Cipher suites length (variable)
            if (pos + 1 >= length) return -1
            val cipherSuitesLen = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
            pos += 2 + cipherSuitesLen
            
            // Compression methods length (variable)
            if (pos >= length) return -1
            val compMethodsLen = buffer[pos].toInt() and 0xFF
            pos += 1 + compMethodsLen
            
            // Extensions length
            if (pos + 1 >= length) return -1
            val extensionsLen = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
            pos += 2
            
            val extEnd = minOf(pos + extensionsLen, length)
            
            while (pos + 3 < extEnd) {
                val extType = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
                val extLen = ((buffer[pos + 2].toInt() and 0xFF) shl 8) or (buffer[pos + 3].toInt() and 0xFF)
                
                pos += 4
                
                if (extType == 0x0000) { // Server Name extension
                    // Check SNI list length
                    if (pos + 1 < extEnd) {
                        val sniListLen = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
                        var sniPos = pos + 2
                        
                        // Look for HostName (Type 0)
                        while (sniPos + 2 < pos + extLen && sniPos + 2 < extEnd) {
                            val nameType = buffer[sniPos].toInt() and 0xFF
                            val nameLen = ((buffer[sniPos + 1].toInt() and 0xFF) shl 8) or (buffer[sniPos + 2].toInt() and 0xFF)
                            
                            if (nameType == 0) { // HostName
                                return sniPos + 3
                            }
                            sniPos += 3 + nameLen
                        }
                    }
                }
                pos += extLen
            }
        } catch (e: Exception) {
            // Ignore
        }
        
        return -1
    }
}
