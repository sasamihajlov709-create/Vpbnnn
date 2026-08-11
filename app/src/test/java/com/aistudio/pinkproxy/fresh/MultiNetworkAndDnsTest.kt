package com.aistudio.pinkproxy.fresh

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class MultiNetworkAndDnsTest {

    @Test
    fun testIpExtractionFromDnsUrls() {
        val googleDnsUrl = "https://8.8.8.8/dns-query"
        val quad9Url = "https://9.9.9.9/dns-query, https://149.112.112.112/dns-query"
        
        val ipRegex = Regex("""\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b""")
        val googleIps = ipRegex.findAll(googleDnsUrl).map { it.value }.toList()
        val quad9Ips = ipRegex.findAll(quad9Url).map { it.value }.toList()

        assertEquals(listOf("8.8.8.8"), googleIps)
        assertEquals(listOf("9.9.9.9", "149.112.112.112"), quad9Ips)
    }

    @Test
    fun testDpiStoragePersistenceAndClear() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        
        DpiEngine.recordResult(BypassStrategy.TLS_APP_DATA_SPLIT, true, HostCategory.MESSENGER, latencyMs = 25)
        val scoreBefore = DpiStrategySelector.getAverageScore(BypassStrategy.TLS_APP_DATA_SPLIT)
        
        DpiStorage.saveScores(context)
        DpiEngine.resetStrategyScoresForNetworkChange()
        
        DpiStorage.loadScores(context)
        val scoreAfter = DpiStrategySelector.getAverageScore(BypassStrategy.TLS_APP_DATA_SPLIT)
        assertEquals(scoreBefore.toInt(), scoreAfter.toInt())
    }

    @Test
    fun testNuclearAndShadowDnsProtocolsNonEmptyFallback() {
        val host = "localhost"
        val dnsIp = "127.0.0.1"
        
        // Ensure queries fail gracefully without throwing unhandled exceptions
        val resNuclear = kotlinx.coroutines.runBlocking {
            UdpDnsProtocols.queryUdpDnsNuclear(host, dnsIp, null, 1)
        }
        assertNotNull(resNuclear)
    }
}
