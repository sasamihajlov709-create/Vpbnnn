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

    fun applyHybridTlsMangle(data: ByteArray, length: Int, rnd: ThreadLocalRandom = ThreadLocalRandom.current()): ByteArray {
        var res = data.copyOf(length)
        if (length > 44 && res[0] == 0x16.toByte()) {
            res = TlsParser.mangleSni(res, res.size, rnd)
            res = TlsParser.addGrease(res, res.size, rnd)
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
        return res
    }
}
