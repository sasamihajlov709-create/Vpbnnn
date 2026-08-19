package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class DpiAnalyzerTest {

    @Before
    fun setUp() {
        DpiEngine.resetStrategyScoresForNetworkChange()
    }

    @Test
    fun testCensorshipFingerprintCalculation() {
        DpiAnalyzer.recordEvent(DpiType.TCP_RESET)
        DpiAnalyzer.recordEvent(DpiType.TLS_SNI_BLOCK)

        val fingerprint = DpiAnalyzer.getCensorshipFingerprint()
        assertNotNull(fingerprint)
        assertTrue("RST rate should be > 0", fingerprint.rstRate > 0.0)
        assertTrue("SNI block rate should be > 0", fingerprint.sniBlockRate > 0.0)
    }

    @Test
    fun testSpoofedRstDetection() {
        DpiAnalyzer.recordSpoofedRst("spoofed.target.com", rttMs = 12L)
        val rstEvents = DpiEngine.eventHistory[DpiType.TCP_RESET]?.get() ?: 0
        assertTrue("Spoofed RST should increment TCP_RESET event count", rstEvents >= 1)
    }

    @Test
    fun testAnalyzeAndAdjustExecutesCleanly() {
        DpiAnalyzer.analyzeAndAdjust()
        DpiAnalyzer.checkGlobalStall()
        assertTrue("Frag1 should remain within sane bounds", BypassConfig.frag1 in 1..1500)
    }
}
