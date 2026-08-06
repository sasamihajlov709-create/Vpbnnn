package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.net.InetAddress

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class PinkProxyServerTest {

    @Test
    fun testBypassConfigDefaultsAndStrictBypassToggle() {
        assertFalse(BypassConfig.isStrictBypassMode)
        
        BypassConfig.isStrictBypassMode = true
        assertTrue(BypassConfig.isStrictBypassMode)
        
        BypassConfig.isStrictBypassMode = false
        assertFalse(BypassConfig.isStrictBypassMode)
    }

    @Test
    fun testDnsCacheManagerPoisoningFiltering() {
        // Valid CDN / public service IPs must NOT be marked as poisoned
        val cloudflareIp = InetAddress.getByName("188.114.96.1")
        val googleIp = InetAddress.getByName("142.250.180.14")
        val yandexDnsIp = InetAddress.getByName("77.88.8.8")
        
        assertFalse("188.114.96.1 must NOT be poisoned", DnsCacheManager.isPoisoned(cloudflareIp, "example.com"))
        assertFalse("142.250.180.14 must NOT be poisoned", DnsCacheManager.isPoisoned(googleIp, "google.com"))
        assertFalse("77.88.8.8 must NOT be poisoned", DnsCacheManager.isPoisoned(yandexDnsIp, "yandex.ru"))

        // Known fake/loopback IPs MUST be recognized as poisoned
        val loopbackIp = InetAddress.getByName("127.0.0.1")
        val zeroIp = InetAddress.getByName("0.0.0.0")
        val ciscoBlockIp = InetAddress.getByName("146.112.61.106")
        
        assertTrue("127.0.0.1 MUST be poisoned", DnsCacheManager.isPoisoned(loopbackIp, "example.com"))
        assertTrue("0.0.0.0 MUST be poisoned", DnsCacheManager.isPoisoned(zeroIp, "example.com"))
        assertTrue("146.112.61.106 MUST be poisoned", DnsCacheManager.isPoisoned(ciscoBlockIp, "example.com"))
    }
}

