package com.aistudio.pinkproxy.fresh

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.net.InetAddress

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class DnsCachePersistenceTest {

    private val context = RuntimeEnvironment.getApplication()

    @Before
    fun setUp() {
        DnsCacheManager.clearAll()
    }

    @After
    fun tearDown() {
        DnsCacheManager.clearAll()
    }

    @Test
    fun `save and load persists cached DNS entries`() {
        val host = "persistent-test.com"
        val ips = listOf(InetAddress.getByName("198.51.100.42"))
        
        DnsCacheManager.put(host, ips, ttlMs = 300000L)
        
        val cachedBefore = DnsCacheManager.getCached(host)
        assertNotNull(cachedBefore)
        assertEquals(ips, cachedBefore)
        
        DnsCacheManager.save(context)
        
        DnsCacheManager.clearAll()
        assertEquals(null, DnsCacheManager.getCached(host))
        
        DnsCacheManager.load(context)
        
        val cachedAfter = DnsCacheManager.getCached(host)
        assertNotNull(cachedAfter)
        assertEquals(ips, cachedAfter)
    }

    @Test
    fun `getSessionConfig uses adaptive RTT delay`() {
        val host = "rtt-test.com"
        
        val configHighRtt = BypassConfig.getSessionConfig(host, strategy = BypassStrategy.SNI_SPLIT, rtt = 400L, transport = com.aistudio.pinkproxy.fresh.TransportType.TCP)
        
        assertEquals(100L, configHighRtt.delay1)
    }
}
