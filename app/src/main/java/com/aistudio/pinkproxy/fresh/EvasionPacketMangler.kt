package com.aistudio.pinkproxy.fresh

import java.util.concurrent.ThreadLocalRandom

object EvasionPacketMangler {

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
        val s = String(data, 0, length, Charsets.US_ASCII)
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

    fun splitIntoTlsRecords(data: ByteArray, length: Int, splitPos: Int): List<ByteArray> {
        if (length <= 5 || data[0] != 0x16.toByte()) {
            return listOf(data.copyOf(length))
        }

        val recordHeaderSize = 5
        val innerPayloadLen = length - recordHeaderSize
        val safeSplit = splitPos.coerceIn(1, (innerPayloadLen - 1).coerceAtLeast(1))

        val part1Len = safeSplit
        val part2Len = innerPayloadLen - safeSplit

        // Record 1
        val rec1 = ByteArray(recordHeaderSize + part1Len)
        rec1[0] = 0x16.toByte() // Handshake
        rec1[1] = data[1]       // Major version
        rec1[2] = data[2]       // Minor version
        rec1[3] = ((part1Len shr 8) and 0xFF).toByte()
        rec1[4] = (part1Len and 0xFF).toByte()
        System.arraycopy(data, recordHeaderSize, rec1, recordHeaderSize, part1Len)

        // Record 2
        val rec2 = ByteArray(recordHeaderSize + part2Len)
        rec2[0] = 0x16.toByte()
        rec2[1] = data[1]
        rec2[2] = data[2]
        rec2[3] = ((part2Len shr 8) and 0xFF).toByte()
        rec2[4] = (part2Len and 0xFF).toByte()
        System.arraycopy(data, recordHeaderSize + part1Len, rec2, recordHeaderSize, part2Len)

        return listOf(rec1, rec2)
    }

    fun createFakeTlsNoisePrefix(rnd: ThreadLocalRandom = ThreadLocalRandom.current()): ByteArray {
        val noiseLen = rnd.nextInt(16, 64)
        val noiseRecord = ByteArray(5 + noiseLen)
        // Dummy TLS Application Data (0x17)
        noiseRecord[0] = 0x17.toByte()
        noiseRecord[1] = 0x03.toByte() // TLS 1.2
        noiseRecord[2] = 0x03.toByte()
        noiseRecord[3] = ((noiseLen shr 8) and 0xFF).toByte()
        noiseRecord[4] = (noiseLen and 0xFF).toByte()
        rnd.nextBytes(noiseRecord.sliceArray(5 until 5 + noiseLen))
        return noiseRecord
    }

    fun applyHybridTlsMangle(data: ByteArray, length: Int, rnd: ThreadLocalRandom = ThreadLocalRandom.current()): ByteArray {
        var res = data.copyOf(length)
        if (length > 44 && res[0] == 0x16.toByte()) {
            res = TlsParser.mangleSni(res, res.size, rnd)
            res = TlsParser.addGrease(res, res.size, rnd)
            res = TlsParser.shuffleExtensions(res, res.size, rnd)
            if (rnd.nextBoolean()) {
                res = TlsParser.shuffleCiphers(res, res.size, rnd)
            }
            if (rnd.nextBoolean()) {
                res = TlsParser.addPadding(res, res.size, rnd.nextInt(32, 128))
            }
        }
        return res
    }

    fun applyHybridHttpMangle(data: ByteArray, length: Int): ByteArray {
        var res = mangleHttpMethodCase(data, length)
        res = randomizeHeaderCase(res, res.size)
        res = addSpaceToHttpMethod(res, res.size)
        res = addDotToHost(res, res.size)
        return res
    }
}

