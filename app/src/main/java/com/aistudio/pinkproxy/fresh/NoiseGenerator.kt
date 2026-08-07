package com.aistudio.pinkproxy.fresh

import java.util.concurrent.ThreadLocalRandom

object NoiseGenerator {
    private var _staticNoiseCache: ByteArray? = null
    
    private fun getStaticNoise(): ByteArray {
        var res = _staticNoiseCache
        if (res == null) {
            val newCache = ByteArray(32768)
            ThreadLocalRandom.current().nextBytes(newCache)
            _staticNoiseCache = newCache
            res = newCache
        }
        return res
    }

    fun getSmallNoise(size: Int): ByteArray {
        val noise = getStaticNoise()
        val safeSize = size.coerceAtMost(noise.size)
        val out = ByteArray(safeSize)
        val maxOffset = (noise.size - safeSize).coerceAtLeast(0)
        val offset = if (maxOffset > 0) ThreadLocalRandom.current().nextInt(maxOffset) else 0
        System.arraycopy(noise, offset, out, 0, safeSize)
        return out
    }

    fun buildUdpNoise(size: Int): ByteArray {
        val out = ByteArray(size)
        ThreadLocalRandom.current().nextBytes(out)
        return out
    }
}
