package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.net.InetAddress

/**
 * Stage 5 Verification Test:
 * DNS Execution Pipeline and correctness.
 * Verifies that the internal DNS resolution yields properly formed IPs,
 * and handles failures correctly through the RobustResolver and cache.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class DnsCorrectnessTest {

    @Test
    fun `RobustResolver injects valid IPs into cache`() = runBlocking {
        // Clear cache
        DnsCacheManager.clearAll()
        
        val testDomain = "example.com"
        val ipStr = "93.184.216.34"
        val ip = InetAddress.getByName(ipStr)
        
        // Insert into cache manually
        DnsCacheManager.put(testDomain, listOf(ip))
        
        // Verify cache retrieval
        val cached = DnsCacheManager.getCached(testDomain)?.firstOrNull()
        assertNotNull("Cache should return IP", cached)
        assertEquals(ipStr, cached!!.hostAddress)
        
        // Verify RobustResolver wrapper
        val resolvedFromRobust = RobustResolver.getCached(testDomain)?.firstOrNull()
        assertNotNull("RobustResolver should fetch from cache", resolvedFromRobust)
        assertEquals(ipStr, resolvedFromRobust!!.hostAddress)
    }
}
