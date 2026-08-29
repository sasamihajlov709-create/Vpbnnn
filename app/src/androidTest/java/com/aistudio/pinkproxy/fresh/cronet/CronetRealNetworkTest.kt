package com.aistudio.pinkproxy.fresh.cronet

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.aistudio.pinkproxy.fresh.DnsPacketEngine
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Real E2E Network test for Cronet HTTP/3.
 * IMPORTANT: This test requires a real Android device or emulator with Google Play Services.
 * It will perform actual DNS-over-HTTPS resolution against dns.google over QUIC.
 */
@RunWith(AndroidJUnit4::class)
class CronetRealNetworkTest {

    private lateinit var context: Context

    @Before
    fun setup() = runBlocking {
        context = ApplicationProvider.getApplicationContext()
        val initialized = CronetEngineProvider.initialize(context)
        assertTrue("Cronet should initialize on a real device with GMS", initialized)
    }

    @After
    fun teardown() = runBlocking {
        CronetEngineProvider.close()
    }

    @Test
    fun testRealDohResolution() = runBlocking {
        val engine = CronetEngineProvider.getEngine()
        assertNotNull("Cronet Engine should be available", engine)
        
        val transport = CronetDohTransport(engine!!)
        
        // Build a DNS wire format query for 'example.com' (Type A)
        val queryCtx = DnsPacketEngine.buildQueryContext("example.com", 1)
        
        // Resolve using Google DoH
        val response = transport.resolveDoH("https://dns.google/dns-query", queryCtx.rawBytes)
        
        assertNotNull("DNS Response should not be null", response)
        assertTrue("DNS Response should have data", response!!.isNotEmpty())
        
        // Parse the response
        val records = DnsPacketEngine.parseDnsResponseDetailed(
            response, 
            response.size, 
            expectedId = queryCtx.id, 
            expectedHost = "example.com"
        )
        
        assertTrue("Should return at least one IP record", records.isNotEmpty())
        
        // Check telemetry
        assertTrue("Should have recorded a Cronet attempt", CronetMetrics.cronetAttemptCount > 0)
        
        // Note: Depending on network, it might fallback to HTTP/2. We can't strictly assert HTTP/3.
        // But we can assert it was recorded as either success or fallback.
        val totalResolutions = CronetMetrics.http3RequestSuccessCount + CronetMetrics.fallbackToTcpCount
        assertTrue("Should have recorded either H3 success or TCP fallback", totalResolutions > 0)
    }
}
