package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class RecoveryManagerTest {

    @Test
    fun testHostBlacklistMechanism() {
        val testHost = "malicious-sni.com"
        assertFalse(RecoveryManager.isHostBlacklisted(testHost))

        RecoveryManager.blacklistHost(testHost, durationMs = 10000L)
        assertTrue(RecoveryManager.isHostBlacklisted(testHost))
    }

    @Test
    fun testHandleRecoveryEvents() = runTest {
        val jobDpi = RecoveryManager.handleEvent(RecoveryEvent.DPI_DETECTED, "Test DPI detected")
        assertNotNull(jobDpi)

        val jobStall = RecoveryManager.handleEvent(RecoveryEvent.TUNNEL_STALL, "Simulated stall")
        assertNotNull(jobStall)

        val jobDns = RecoveryManager.handleEvent(RecoveryEvent.DNS_POISONED, "DNS poisoned")
        assertNotNull(jobDns)
    }

    @Test
    fun testRecalibrateEverything() = runTest {
        val resetJob = RecoveryManager.recalibrateEverything()
        assertNotNull(resetJob)
    }
}
