package com.aistudio.pinkproxy.fresh

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ServiceCheckerAndStatusTest {

    private lateinit var context: Context

    @Before
    fun setup() {
        context = ApplicationProvider.getApplicationContext()
    }

    @Test
    fun testCustomServicesAddRemoveAndPersistence() {
        PinkServiceStatusManager.addCustomService(context, "MyWiki", "https://en.wikipedia.org")
        
        var services = PinkServiceStatusManager.customServices.value
        assertEquals(1, services.size)
        assertEquals("MyWiki", services[0].first)
        assertEquals("https://en.wikipedia.org", services[0].second)

        // Reload from prefs
        PinkServiceStatusManager.loadCustomServices(context)
        services = PinkServiceStatusManager.customServices.value
        assertEquals(1, services.size)
        assertEquals("MyWiki", services[0].first)

        // Remove custom service
        PinkServiceStatusManager.removeCustomService(context, "MyWiki")
        services = PinkServiceStatusManager.customServices.value
        assertTrue(services.isEmpty())
    }

    @Test
    fun testTrafficShaperMssRecommendation() {
        TrafficShaper.reset(50L)
        assertEquals(1440, TrafficShaper.getRecommendedMss())

        repeat(8) {
            TrafficShaper.updateRtt(600L)
        }
        assertTrue(TrafficShaper.getAvgRtt() > 300L)
        assertEquals(1200, TrafficShaper.getRecommendedMss())
    }
}
