package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Test
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

class HappyEyeballsAndRaceConnectorTest {

    @Test
    fun testDualStackAddressInterleaving() {
        val v4 = listOf(
            InetAddress.getByName("1.1.1.1"),
            InetAddress.getByName("1.0.0.1")
        )
        val v6 = listOf(
            InetAddress.getByName("2606:4700:4700::1111"),
            InetAddress.getByName("2606:4700:4700::1001")
        )
        val combined = v6 + v4

        val v6Addresses = combined.filterIsInstance<Inet6Address>()
        val v4Addresses = combined.filterIsInstance<Inet4Address>()

        assertEquals(2, v6Addresses.size)
        assertEquals(2, v4Addresses.size)

        val interleaved = mutableListOf<Pair<InetAddress, Long>>()
        val maxLen = maxOf(v6Addresses.size, v4Addresses.size)
        var delayAccumulator = 0L

        for (i in 0 until maxLen) {
            if (i < v6Addresses.size) {
                interleaved.add(v6Addresses[i] to delayAccumulator)
                delayAccumulator += 60L
            }
            if (i < v4Addresses.size) {
                interleaved.add(v4Addresses[i] to delayAccumulator)
                delayAccumulator += 60L
            }
        }

        assertEquals(4, interleaved.size)
        assertTrue(interleaved[0].first is Inet6Address)
        assertEquals(0L, interleaved[0].second)

        assertTrue(interleaved[1].first is Inet4Address)
        assertEquals(60L, interleaved[1].second)

        assertTrue(interleaved[2].first is Inet6Address)
        assertEquals(120L, interleaved[2].second)

        assertTrue(interleaved[3].first is Inet4Address)
        assertEquals(180L, interleaved[3].second)
    }

    @Test
    fun testBufferPoolZeroAllocationIntegrity() {
        val initial8k = BufferPoolManager.obtain8k()
        assertEquals(8192, initial8k.size)

        BufferPoolManager.release8k(initial8k)
        assertTrue(BufferPoolManager.get8kSize() >= 1)

        val recycled8k = BufferPoolManager.obtain8k()
        assertSame(initial8k, recycled8k)

        val buf64k = BufferPool.obtain()
        assertEquals(65536, buf64k.size)
        BufferPool.release(buf64k)
        val recycled64k = BufferPool.obtain()
        assertSame(buf64k, recycled64k)
    }
}
