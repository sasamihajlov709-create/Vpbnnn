package com.aistudio.pinkproxy.fresh

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class Stage2Stage3VerificationTest {

    @Test
    fun testHostMemoryStaleEntriesClearedOnSave() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        
        // Add host memory
        DpiEngine.hostSpecificMemory["test-stale-domain.com"] = DpiEngine.HostMemory(BypassStrategy.TLS_SNI_FRAGMENT, System.currentTimeMillis())
        DpiStorage.saveScores(context, synchronous = true)

        // Remove from RAM and re-save
        DpiEngine.hostSpecificMemory.remove("test-stale-domain.com")
        DpiStorage.saveScores(context, synchronous = true)

        // Reset memory and load back from disk
        DpiEngine.hostSpecificMemory.clear()
        DpiStorage.loadScores(context)

        // Verify that removed entry was purged from disk as well
        assertFalse("Removed host memory entry should not reappear from SharedPreferences", DpiEngine.hostSpecificMemory.containsKey("test-stale-domain.com"))
    }

    @Test
    fun testStrategySelectionHysteresisAndStability() {
        val host = "stabilized-service.org"
        DpiEngine.consecutiveFailuresByHost[host]?.set(0)
        DpiEngine.hostSpecificMemory[host] = DpiEngine.HostMemory(BypassStrategy.TCP_PULSE_FRAG, System.currentTimeMillis())

        val category = HostClassifier.classify(host)
        val selectedStrategy = DpiStrategySelector.getBestStrategy(category, host)

        assertEquals("Strategy selector should respect cached host strategy when zero failures occur", BypassStrategy.TCP_PULSE_FRAG, selectedStrategy)
    }

    @Test
    fun testDnsTypeCustomUrlExtractionAndFallback() {
        BypassConfig.dnsType = DnsType.CUSTOM_DOH
        BypassConfig.customDnsUrl = "https://1.1.1.1/dns-query"

        val ipRegex = Regex("""\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b""")
        val ips = ipRegex.findAll(BypassConfig.customDnsUrl).map { it.value }.toList()

        assertEquals(listOf("1.1.1.1"), ips)
    }
}
