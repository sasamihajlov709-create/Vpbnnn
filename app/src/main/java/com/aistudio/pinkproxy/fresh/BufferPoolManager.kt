package com.aistudio.pinkproxy.fresh

import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger

object BufferPoolManager {
    private val bufferPool8k = ConcurrentLinkedQueue<ByteArray>()
    private val size8k = AtomicInteger(0)
    private const val MAX_8K = 256

    private val bufferPool16k = ConcurrentLinkedQueue<ByteArray>()
    private val size16k = AtomicInteger(0)
    private const val MAX_16K = 128

    private val bufferPool64k = ConcurrentLinkedQueue<ByteArray>()
    private val size64k = AtomicInteger(0)
    private const val MAX_64K = 64

    fun obtain8k(): ByteArray {
        val buf = bufferPool8k.poll()
        if (buf != null) {
            size8k.decrementAndGet()
            return buf
        }
        return ByteArray(8192)
    }

    fun release8k(buf: ByteArray) { 
        if (buf.size >= 8192 && size8k.get() < MAX_8K) {
            bufferPool8k.offer(buf)
            size8k.incrementAndGet()
        }
    }

    fun obtain16k(): ByteArray {
        val buf = bufferPool16k.poll()
        if (buf != null) {
            size16k.decrementAndGet()
            return buf
        }
        return ByteArray(16384)
    }

    fun release16k(buf: ByteArray) { 
        if (buf.size >= 16384 && size16k.get() < MAX_16K) {
            bufferPool16k.offer(buf)
            size16k.incrementAndGet()
        }
    }

    fun obtain64k(): ByteArray {
        val buf = bufferPool64k.poll()
        if (buf != null) {
            size64k.decrementAndGet()
            return buf
        }
        return ByteArray(65536)
    }

    fun release64k(buf: ByteArray) { 
        if (buf.size >= 65536 && size64k.get() < MAX_64K) {
            bufferPool64k.offer(buf)
            size64k.incrementAndGet()
        }
    }

    fun releasePool(buf: ByteArray) {
        when (buf.size) {
            8192 -> release8k(buf)
            16384 -> release16k(buf)
            65536 -> release64k(buf)
        }
    }

    fun releaseAllPools() {
        bufferPool8k.clear()
        size8k.set(0)
        bufferPool16k.clear()
        size16k.set(0)
        bufferPool64k.clear()
        size64k.set(0)
        BufferPool.clear()
    }

    fun get8kSize(): Int = size8k.get()
    fun get16kSize(): Int = size16k.get()
    fun get64kSize(): Int = size64k.get()
}

