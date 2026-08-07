package com.aistudio.pinkproxy.fresh

import java.util.concurrent.ConcurrentLinkedQueue

object BufferPoolManager {
    private val bufferPool8k = ConcurrentLinkedQueue<ByteArray>()
    private val bufferPool16k = ConcurrentLinkedQueue<ByteArray>()
    private val bufferPool64k = ConcurrentLinkedQueue<ByteArray>()

    fun obtain8k(): ByteArray = bufferPool8k.poll() ?: ByteArray(8192)
    fun release8k(buf: ByteArray) { 
        if (buf.size >= 8192 && bufferPool8k.size < 512) bufferPool8k.offer(buf) 
    }

    fun obtain16k(): ByteArray = bufferPool16k.poll() ?: ByteArray(16384)
    fun release16k(buf: ByteArray) { 
        if (buf.size >= 16384 && bufferPool16k.size < 256) bufferPool16k.offer(buf) 
    }

    fun obtain64k(): ByteArray = bufferPool64k.poll() ?: ByteArray(65536)
    fun release64k(buf: ByteArray) { 
        if (buf.size >= 65536 && bufferPool64k.size < 64) bufferPool64k.offer(buf) 
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
        bufferPool16k.clear()
        bufferPool64k.clear()
    }

    fun get8kSize(): Int = bufferPool8k.size
    fun get16kSize(): Int = bufferPool16k.size
    fun get64kSize(): Int = bufferPool64k.size
}
