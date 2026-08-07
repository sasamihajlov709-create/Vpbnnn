package com.aistudio.pinkproxy.fresh

object TlsParser {
    fun isClientHello(buffer: ByteArray, length: Int, offset: Int = 0): Boolean {
        if (length < 44) return false
        if (offset + 5 >= buffer.size) return false
        return buffer[offset] == 0x16.toByte() && buffer[offset + 5] == 0x01.toByte()
    }

    /**
     * Parses a TLS ClientHello packet and finds the exact offset of the SNI hostname string.
     * Returns the offset of the first character of the hostname, or -1 if not found.
     */
    fun findSniOffset(buffer: ByteArray, length: Int, offset: Int = 0, host: String? = null): Int {
        if (length < 44) return -1
        
        // Ensure it's a TLS Handshake (0x16) and ClientHello (0x01)
        if (buffer[offset] != 0x16.toByte()) return -1
        if (length < 6 || buffer[offset + 5] != 0x01.toByte()) return -1
        
        try {
            // Record layer version: 3.x
            if (buffer[offset + 1] != 0x03.toByte()) return -1

            // Session ID length (variable)
            val sessionIdLen = buffer[offset + 43].toInt() and 0xFF
            var pos = offset + 44 + sessionIdLen
            
            val end = offset + length
            
            // Cipher suites length (variable)
            if (pos + 1 >= end) return -1
            val cipherSuitesLen = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
            pos += 2 + cipherSuitesLen
            
            // Compression methods length (variable)
            if (pos >= end) return -1
            pos += 1 + (buffer[pos].toInt() and 0xFF)
            
            // Extensions length
            if (pos + 1 >= end) return -1
            val extensionsLen = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
            pos += 2
            
            val extEnd = minOf(pos + extensionsLen, end)
            
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

    fun extractSni(buffer: ByteArray, length: Int): String? {
        val offset = findSniOffset(buffer, length)
        if (offset == -1) return null
        return extractHostname(buffer, length, offset)
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

    fun findSni(buffer: ByteArray, length: Int): Int = findSniOffset(buffer, length)

    fun mangleSni(buffer: ByteArray, length: Int, rnd: java.util.concurrent.ThreadLocalRandom): ByteArray {
        val offset = findSniOffset(buffer, length)
        if (offset == -1) return buffer.copyOf(length)
        val copy = buffer.copyOf(length)
        val nameLen = ((copy[offset - 2].toInt() and 0xFF) shl 8) or (copy[offset - 1].toInt() and 0xFF)
        for (i in 0 until nameLen) {
            val b = copy[offset + i]
            if ((b >= 'A'.code.toByte() && b <= 'Z'.code.toByte()) || (b >= 'a'.code.toByte() && b <= 'z'.code.toByte())) {
                if (rnd.nextBoolean()) {
                    copy[offset + i] = (b.toInt() xor 32).toByte()
                }
            }
        }
        return copy
    }

    fun addPadding(buffer: ByteArray, length: Int, padLen: Int): ByteArray {
        return FakePacketHelper.injectTlsPadding(buffer, length, padLen)
    }

    fun addGrease(buffer: ByteArray, length: Int, rnd: java.util.concurrent.ThreadLocalRandom): ByteArray {
        return FakePacketHelper.addTlsGreaseExtensions(buffer, length)
    }

    fun shuffleExtensions(buffer: ByteArray, length: Int, rnd: java.util.concurrent.ThreadLocalRandom): ByteArray {
        return FakePacketHelper.shuffleTlsExtensions(buffer, length)
    }

    fun mangleExtensions(buffer: ByteArray, length: Int, rnd: java.util.concurrent.ThreadLocalRandom): ByteArray {
        if (!isClientHello(buffer, length)) return buffer.copyOf(length)
        try {
            val copy = buffer.copyOf(length)
            val sessionIdLen = copy[43].toInt() and 0xFF
            var pos = 44 + sessionIdLen
            val cipherSuitesLen = ((copy[pos].toInt() and 0xFF) shl 8) or (copy[pos + 1].toInt() and 0xFF)
            pos += 2 + cipherSuitesLen
            pos += 1 + (copy[pos].toInt() and 0xFF)
            val extensionsLen = ((copy[pos].toInt() and 0xFF) shl 8) or (copy[pos + 1].toInt() and 0xFF)
            pos += 2
            val extEnd = minOf(pos + extensionsLen, length)
            
            while (pos + 3 < extEnd) {
                val extLen = ((copy[pos + 2].toInt() and 0xFF) shl 8) or (copy[pos + 3].toInt() and 0xFF)
                if (rnd.nextInt(100) < 30) {
                    // Xoring extension data with some bits
                    for (i in 0 until minOf(extLen, 4)) {
                        if (pos + 4 + i < extEnd) {
                             copy[pos + 4 + i] = (copy[pos + 4 + i].toInt() xor rnd.nextInt(1, 255)).toByte()
                        }
                    }
                }
                pos += 4 + extLen
            }
            return copy
        } catch (e: Throwable) { return buffer.copyOf(length) }
    }

    fun shuffleCiphers(buffer: ByteArray, length: Int, rnd: java.util.concurrent.ThreadLocalRandom): ByteArray {
        if (!isClientHello(buffer, length)) return buffer.copyOf(length)
        val copy = buffer.copyOf(length)
        try {
            val sessionIdLen = copy[43].toInt() and 0xFF
            val pos = 44 + sessionIdLen
            if (pos + 1 >= length) return copy
            val cipherSuitesLen = ((copy[pos].toInt() and 0xFF) shl 8) or (copy[pos + 1].toInt() and 0xFF)
            val cipherStart = pos + 2
            if (cipherSuitesLen < 4 || cipherStart + cipherSuitesLen > length) return copy

            val count = cipherSuitesLen / 2
            val ciphers = ArrayList<Pair<Byte, Byte>>(count)
            for (i in 0 until count) {
                val idx = cipherStart + i * 2
                ciphers.add(Pair(copy[idx], copy[idx + 1]))
            }

            // Shuffle ciphers
            for (i in count - 1 downTo 1) {
                val j = rnd.nextInt(i + 1)
                val tmp = ciphers[i]
                ciphers[i] = ciphers[j]
                ciphers[j] = tmp
            }

            for (i in 0 until count) {
                val idx = cipherStart + i * 2
                copy[idx] = ciphers[i].first
                copy[idx + 1] = ciphers[i].second
            }
            return copy
        } catch (e: Throwable) {
            return buffer.copyOf(length)
        }
    }

    fun mangleAlpn(buffer: ByteArray, length: Int, rnd: java.util.concurrent.ThreadLocalRandom): ByteArray {
        if (!isClientHello(buffer, length)) return buffer.copyOf(length)
        val copy = buffer.copyOf(length)
        try {
            val sessionIdLen = copy[43].toInt() and 0xFF
            var pos = 44 + sessionIdLen
            if (pos + 1 >= length) return copy
            val cipherSuitesLen = ((copy[pos].toInt() and 0xFF) shl 8) or (copy[pos + 1].toInt() and 0xFF)
            pos += 2 + cipherSuitesLen
            if (pos >= length) return copy
            val compLen = copy[pos].toInt() and 0xFF
            pos += 1 + compLen
            if (pos + 1 >= length) return copy

            val extensionsLen = ((copy[pos].toInt() and 0xFF) shl 8) or (copy[pos + 1].toInt() and 0xFF)
            pos += 2
            val extEnd = minOf(pos + extensionsLen, length)

            while (pos + 3 < extEnd) {
                val extType = ((copy[pos].toInt() and 0xFF) shl 8) or (copy[pos + 1].toInt() and 0xFF)
                val extLen = ((copy[pos + 2].toInt() and 0xFF) shl 8) or (copy[pos + 3].toInt() and 0xFF)

                if (extType == 0x0010) { // ALPN extension
                    val alpnDataStart = pos + 4
                    val alpnDataEnd = pos + 4 + extLen
                    if (alpnDataStart + 2 < extEnd && alpnDataEnd <= extEnd) {
                        // Reverse ALPN list order or swap entries
                        val alpnListLen = ((copy[alpnDataStart].toInt() and 0xFF) shl 8) or (copy[alpnDataStart + 1].toInt() and 0xFF)
                        var p = alpnDataStart + 2
                        val protocols = ArrayList<ByteArray>()
                        while (p < alpnDataStart + 2 + alpnListLen && p < length) {
                            val pLen = copy[p].toInt() and 0xFF
                            if (p + 1 + pLen <= length) {
                                protocols.add(copy.copyOfRange(p + 1, p + 1 + pLen))
                            }
                            p += 1 + pLen
                        }
                        if (protocols.size >= 2) {
                            protocols.reverse()
                            var writePos = alpnDataStart + 2
                            for (proto in protocols) {
                                if (writePos + 1 + proto.size <= copy.size) {
                                    copy[writePos] = proto.size.toByte()
                                    System.arraycopy(proto, 0, copy, writePos + 1, proto.size)
                                    writePos += 1 + proto.size
                                }
                            }
                        }
                    }
                    return copy
                }
                pos += 4 + extLen
            }

            // If ALPN not present, inject ALPN extension
            val fakeAlpn = byteArrayOf(0x00, 0x0c, 0x02, 'h'.code.toByte(), '2'.code.toByte(), 0x08, 'h'.code.toByte(), 't'.code.toByte(), 't'.code.toByte(), 'p'.code.toByte(), '/'.code.toByte(), '1'.code.toByte(), '.'.code.toByte(), '1'.code.toByte())
            return TlsPacketBuilder.injectExtension(buffer, length, 0x0010, fakeAlpn)
        } catch (e: Throwable) {
            return buffer.copyOf(length)
        }
    }

    fun mangleSessionId(buffer: ByteArray, length: Int, rnd: java.util.concurrent.ThreadLocalRandom): ByteArray {
        return FakePacketHelper.mangleSessionId(buffer, length)
    }

    fun addExtraSni(buffer: ByteArray, length: Int, extraHost: String, rnd: java.util.concurrent.ThreadLocalRandom): ByteArray {
        return FakePacketHelper.injectMultipleSni(buffer, length, extraHost)
    }

    fun findEch(buffer: ByteArray, length: Int): Int {
        if (length < 44) return -1
        try {
            val sessionIdLen = buffer[43].toInt() and 0xFF
            var pos = 44 + sessionIdLen
            val cipherSuitesLen = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
            pos += 2 + cipherSuitesLen
            pos += 1 + (buffer[pos].toInt() and 0xFF)
            val extensionsLen = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
            pos += 2
            val extEnd = minOf(pos + extensionsLen, length)
            while (pos + 3 < extEnd) {
                val extType = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
                val extLen = ((buffer[pos + 2].toInt() and 0xFF) shl 8) or (buffer[pos + 3].toInt() and 0xFF)
                if (extType == 0xfe0d || extType == 0xff0d || extType == 0x1102) return pos
                pos += 4 + extLen
            }
        } catch (e: Throwable) {}
        return -1
    }

    fun addSniGrease(buffer: ByteArray, length: Int, rnd: java.util.concurrent.ThreadLocalRandom): ByteArray {
        return injectEchGrease(buffer, length)
    }

    fun addFakeEch(buffer: ByteArray, length: Int, rnd: java.util.concurrent.ThreadLocalRandom): ByteArray {
        return injectEchGrease(buffer, length)
    }

    fun replaceSni(buffer: ByteArray, length: Int, newSni: String): ByteArray {
        val offset = findSniOffset(buffer, length)
        if (offset == -1) return buffer.copyOf(length)
        val copy = buffer.copyOf(length)
        try {
            val oldNameLen = ((copy[offset - 2].toInt() and 0xFF) shl 8) or (copy[offset - 1].toInt() and 0xFF)
            val newSniBytes = newSni.toByteArray(java.nio.charset.StandardCharsets.US_ASCII)
            if (newSniBytes.size == oldNameLen && offset + oldNameLen <= length) {
                System.arraycopy(newSniBytes, 0, copy, offset, oldNameLen)
                return copy
            } else {
                val newSniExt = TlsPacketBuilder.buildSniExtension(newSni)
                return TlsPacketBuilder.injectExtension(buffer, length, 0x0000, newSniExt)
            }
        } catch (e: Throwable) {
            return buffer.copyOf(length)
        }
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

    fun isTls13(buffer: ByteArray, length: Int, offset: Int = 0): Boolean {
        if (!isClientHello(buffer, length, offset)) return false
        try {
            val sessionIdLen = buffer[offset + 43].toInt() and 0xFF
            var pos = offset + 44 + sessionIdLen
            val end = offset + length
            if (pos + 1 >= end) return false
            val cipherSuitesLen = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
            pos += 2 + cipherSuitesLen
            if (pos >= end) return false
            pos += 1 + (buffer[pos].toInt() and 0xFF)
            if (pos + 1 >= end) return false
            val extensionsLen = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
            pos += 2
            val extEnd = minOf(pos + extensionsLen, end)
            
            while (pos + 3 < extEnd) {
                val extType = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
                val extLen = ((buffer[pos + 2].toInt() and 0xFF) shl 8) or (buffer[pos + 3].toInt() and 0xFF)
                if (extType == 0x002b) { // Supported Versions
                    var vPos = pos + 4
                    if (vPos + 1 <= extEnd) {
                        val vLen = buffer[vPos].toInt() and 0xFF
                        vPos++
                        for (i in 0 until vLen step 2) {
                            if (vPos + i + 1 < extEnd) {
                                val v = ((buffer[vPos + i].toInt() and 0xFF) shl 8) or (buffer[vPos + i + 1].toInt() and 0xFF)
                                if (v == 0x0304) return true
                            }
                        }
                    }
                }
                pos += 4 + extLen
            }
        } catch (e: Throwable) {}
        return false
    }

    /**
     * Extracts the ClientHello version (Legacy version)
     */
    fun getLegacyVersion(buffer: ByteArray, length: Int): Int {
        if (length < 11) return -1
        return ((buffer[9].toInt() and 0xFF) shl 8) or (buffer[10].toInt() and 0xFF)
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
            if (pos + 1 >= length) return buffer.copyOf(length)
            val cipherSuitesLen = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
            pos += 2 + cipherSuitesLen
            if (pos >= length) return buffer.copyOf(length)
            pos += 1 + (buffer[pos].toInt() and 0xFF) // Compression
            
            // Extensions position
            if (pos + 1 >= length) return buffer.copyOf(length)
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
            System.arraycopy(buffer, 0, result, 0, minOf(pos, length)) // Header + part of extensions
            System.arraycopy(newExt, 0, result, pos, newExt.size) // Inject grease at the start of extensions
            if (length > pos) {
                System.arraycopy(buffer, pos, result, pos + newExt.size, length - pos) // Rest
            }
            
            // Update lengths
            if (result.size > 8) {
                val totalHandshakeLen = ((result[6].toInt() and 0xFF) shl 16) or ((result[7].toInt() and 0xFF) shl 8) or (result[8].toInt() and 0xFF)
                val newHandshakeLen = totalHandshakeLen + newExt.size
                result[6] = (newHandshakeLen shr 16).toByte()
                result[7] = (newHandshakeLen shr 8).toByte()
                result[8] = (newHandshakeLen and 0xFF).toByte()
            }
            
            if (result.size > 4) {
                val recordLen = ((result[3].toInt() and 0xFF) shl 8) or (result[4].toInt() and 0xFF)
                val newRecordLen = recordLen + newExt.size
                result[3] = (newRecordLen shr 8).toByte()
                result[4] = (newRecordLen and 0xFF).toByte()
            }
            
            if (result.size > extLenPos + 1) {
                val newExtensionsLen = extensionsLen + newExt.size
                result[extLenPos] = (newExtensionsLen shr 8).toByte()
                result[extLenPos + 1] = (newExtensionsLen and 0xFF).toByte()
            }
            
            return result
        } catch (e: Throwable) {
            return buffer.copyOf(length)
        }
    }
}
