package com.aistudio.pinkproxy.fresh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class TransportPipelineVerificationTest {

    @Test
    fun testBufferPoolAcquireAndRelease() {
        val buf1 = BufferPool.obtain()
        assertEquals(65536, buf1.size)
        BufferPool.release(buf1)

        val buf2 = BufferPool.obtain()
        assertEquals(65536, buf2.size)
        BufferPool.release(buf2)
    }

    @Test
    fun testBufferPoolManagerTieredSizes() {
        val buf8 = BufferPoolManager.obtain8k()
        assertEquals(8192, buf8.size)
        BufferPoolManager.release8k(buf8)

        val buf16 = BufferPoolManager.obtain16k()
        assertEquals(16384, buf16.size)
        BufferPoolManager.release16k(buf16)

        val buf64 = BufferPoolManager.obtain64k()
        assertEquals(65536, buf64.size)
        BufferPoolManager.release64k(buf64)
    }

    @Test
    fun testFallbackStrategyAlignment() {
        // Ensure BypassConfig.getFallbackStrategy properly resolves known chains
        val fallback = BypassConfig.getFallbackStrategy(BypassStrategy.SNI_SPLIT)
        assertNotNull(fallback)
        // Ensure diverse fallback does not crash and returns compatible strategy
        val diverse = DpiStrategySelector.getDiverseFallback(BypassStrategy.SNI_SPLIT, HostCategory.STREAMING, TransportType.TCP)
        assertTrue(DpiStrategySelector.isFamilyCompatible(diverse.family, TransportType.TCP))
    }
}
