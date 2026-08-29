package com.aistudio.pinkproxy.fresh.cronet

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.chromium.net.CronetEngine

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class CronetIntegrationTest {

    @Test
    fun testCronetInitializationAndShutdown() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        
        // 1. Initialize Cronet (should fail gracefully in Robolectric since Play Services and fallback aren't fully available)
        val initialized = CronetEngineProvider.initialize(context)
        assertFalse("Cronet should fail to initialize in pure Robolectric without native libraries", initialized)
        
        val engine = CronetEngineProvider.getEngine()
        assertNull("Engine should be null", engine)
        
        // 2. Shut down
        CronetEngineProvider.close()
        val engineAfterClose = CronetEngineProvider.getEngine()
        assertNull("Engine should be null after close", engineAfterClose)
    }

    @Test
    fun testMetricsFallbackAndSuccess() = runBlocking {
        CronetMetrics.reset()
        
        CronetMetrics.recordAttempt()
        assertEquals(1, CronetMetrics.cronetAttemptCount)
        
        CronetMetrics.recordQuicHandshake()
        assertEquals(1, CronetMetrics.quicHandshakeSuccessCount)
        
        CronetMetrics.recordSuccess(150L, wasQuic = true)
        assertEquals(1, CronetMetrics.http3RequestSuccessCount)
        assertEquals(150L, CronetMetrics.ewmaLatencyMs)
        
        CronetMetrics.recordFallbackToTcp()
        assertEquals(1, CronetMetrics.fallbackToTcpCount)
        
        CronetMetrics.recordTimeout()
        assertEquals(1, CronetMetrics.requestTimeoutCount)
    }
}
