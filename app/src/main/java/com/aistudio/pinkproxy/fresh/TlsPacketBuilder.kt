package com.aistudio.pinkproxy.fresh

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.concurrent.ThreadLocalRandom

object TlsPacketBuilder {

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
            
            if (oldExtLen + 4 + extData.size > 16384) return data.copyOf(length)
            
            val newTotalLen = pos + 2 + oldExtLen + 4 + extData.size
            if (newTotalLen > 65535) return data.copyOf(length)
            
            val result = ByteArray(newTotalLen)
            System.arraycopy(data, 0, result, 0, pos)
            
            val newExtLen = oldExtLen + 4 + extData.size
            result[pos] = (newExtLen shr 8).toByte()
            result[pos + 1] = (newExtLen and 0xFF).toByte()
            
            if (oldExtLen > 0) {
                System.arraycopy(data, pos + 2, result, pos + 2, oldExtLen)
            }
            
            val extStart = pos + 2 + oldExtLen
            if (extStart + 4 + extData.size <= result.size) {
                result[extStart] = (type shr 8).toByte()
                result[extStart + 1] = (type and 0xFF).toByte()
                result[extStart + 2] = (extData.size shr 8).toByte()
                result[extStart + 3] = (extData.size and 0xFF).toByte()
                System.arraycopy(extData, 0, result, extStart + 4, extData.size)
            }
            
            updateTlsLengths(result)
            return result
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

    fun buildRealisticTlsHello(host: String): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val sni = buildSniExtension(host)
        
        // Corrected TLS Hello construction and using a safer buffer allocation
        val extensionsLen = (sni.size + 4) + 50
        val innerLen = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensionsLen
        
        val data = ByteArray(5 + 4 + innerLen)
        val buf = ByteBuffer.wrap(data)
        
        buf.put(0x16.toByte()) // Record Type: Handshake
        buf.putShort(0x0303.toShort()) // Protocol Version: TLS 1.2
        buf.putShort((4 + innerLen).toShort()) // Record Length
        
        buf.put(0x01.toByte()) // Handshake Type: Client Hello
        buf.put(0.toByte()) // Handshake Length (high byte)
        buf.putShort(innerLen.toShort()) // Handshake Length (low bytes)
        
        buf.putShort(0x0303.toShort()) // Client Version
        val random = ByteArray(32); rnd.nextBytes(random); buf.put(random)
        buf.put(0.toByte()) // Session ID Length: 0
        
        buf.putShort(2.toShort()) // Cipher Suites Length
        buf.putShort(0x1301.toShort()) // Cipher Suite: TLS_AES_128_GCM_SHA256
        
        buf.put(1.toByte()) // Compression Methods Length
        buf.put(0.toByte()) // Compression Method: null
        
        buf.putShort(extensionsLen.toShort()) // Extensions Length
        
        // SNI Extension
        buf.putShort(0.toShort()) // Type: server_name
        buf.putShort(sni.size.toShort()) // Length
        buf.put(sni)
        
        // Random junk extension (type between 100-200, length 46)
        buf.putShort(rnd.nextInt(100, 200).toShort())
        buf.putShort(46.toShort())
        buf.put(NoiseGenerator.buildUdpNoise(46))
        
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

    fun injectTlsPadding(data: ByteArray, length: Int, padLen: Int): ByteArray {
        val padding = ByteArray(padLen)
        return injectExtension(data, length, 0x0015, padding)
    }

    fun addTlsGreaseExtensions(data: ByteArray, length: Int): ByteArray {
        val rnd = ThreadLocalRandom.current()
        var result = data.copyOf(length)
        repeat(rnd.nextInt(1, 3)) {
            val type = (rnd.nextInt(16) shl 8) or 0x0A
            val extData = ByteArray(rnd.nextInt(2, 10))
            rnd.nextBytes(extData)
            result = injectExtension(result, result.size, type, extData)
        }
        return result
    }

    fun shuffleTlsExtensions(data: ByteArray, length: Int): ByteArray {
        // Shuffling extensions is complex, for now we just add a random grease to change the layout
        return addTlsGreaseExtensions(data, length)
    }

    fun injectMultipleSni(data: ByteArray, length: Int, extraHost: String): ByteArray {
        val extraSni = buildSniExtension(extraHost)
        return injectExtension(data, length, 0x0000, extraSni)
    }

    fun buildChromeHello(host: String): ByteArray = buildRealisticTlsHello(host)
    fun buildFirefoxHello(host: String): ByteArray = buildRealisticTlsHello(host)
    fun buildTls13Hello(host: String): ByteArray = buildRealisticTlsHello(host)
}
