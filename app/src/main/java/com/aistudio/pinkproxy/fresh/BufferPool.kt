package com.aistudio.pinkproxy.fresh

import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger

/**
 * High-performance Zero-Copy Buffer Pool for high-bandwidth streaming (YouTube 4K/60FPS).
 * Reduces Android GC pressure by recycling byte arrays across active TCP/UDP proxy sessions.
 */
object BufferPool {
    private const val BUFFER_SIZE = 65536 // 64 KB optimal chunk
    private const val MAX_POOL_SIZE = 64
    private val pool = ConcurrentLinkedQueue<ByteArray>()
    private val currentPoolSize = AtomicInteger(0)

    fun obtain(): ByteArray {
        val buf = pool.poll()
        if (buf != null) {
            currentPoolSize.decrementAndGet()
            return buf
        }
        return ByteArray(BUFFER_SIZE)
    }

    fun release(buf: ByteArray) {
        if (buf.size == BUFFER_SIZE && currentPoolSize.get() < MAX_POOL_SIZE) {
            pool.offer(buf)
            currentPoolSize.incrementAndGet()
        }
    }

    fun clear() {
        pool.clear()
        currentPoolSize.set(0)
    }
}
