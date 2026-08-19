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
class ServiceCheckerTest {

    @Test
    fun testServiceStatusDataModel() {
        val status = ServiceChecker.ServiceStatus(
            name = "YouTube",
            url = "http://youtube.com",
            isUp = true,
            latencyMs = 45L
        )

        assertEquals("YouTube", status.name)
        assertEquals("http://youtube.com", status.url)
        assertTrue(status.isUp)
        assertEquals(45L, status.latencyMs)
    }

    @Test
    fun testDefaultServicesList() {
        val defaults = PinkServiceStatusManager.getDefaultServices()
        assertTrue("Default services should contain popular blocked services", defaults.isNotEmpty())
        assertTrue(defaults.any { it.first == "YouTube" })
        assertTrue(defaults.any { it.first == "Telegram" })
    }

    @Test
    fun testInitialServiceCheckerStates() {
        assertTrue(ServiceChecker.proxyHealth.value)
        assertTrue(ServiceChecker.internetAvailable.value)
        assertFalse(ServiceChecker.isProbingState.value)
    }
}
