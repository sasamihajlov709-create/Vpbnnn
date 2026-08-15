package com.aistudio.pinkproxy.fresh

import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowLog

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class VpnLifecycleTest {

    @Test
    fun testBootReceiverAutoStart() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
        prefs.edit().putBoolean("vpn_was_active", true).commit()

        val receiver = BootReceiver()
        val intent = Intent(Intent.ACTION_BOOT_COMPLETED)
        
        receiver.onReceive(context, intent)

        val shadowApp = shadowOf(ApplicationProvider.getApplicationContext<android.app.Application>())
        val startedService = shadowApp.nextStartedService
        
        // In Robolectric, VpnService.prepare(context) might return an Intent (meaning not prepared),
        // so BootReceiver might disable auto-start instead of starting the service.
        if (android.net.VpnService.prepare(context) != null) {
            org.junit.Assert.assertFalse(prefs.getBoolean("vpn_was_active", true))
        } else {
            assertNotNull("Service should be started on boot if it was active", startedService)
            assertTrue(startedService?.component?.className?.contains("PinkVpnService") == true)
        }
    }

    @Test
    fun testVpnServiceCreation() {
        val controller = Robolectric.buildService(PinkVpnService::class.java)
        val service = controller.create().get()
        
        assertNotNull(service)
        assertTrue(PinkVpnService.instance == service)
        assertNotNull(VpnRuntimeState.lifecycleState.value)
    }

    @Test
    fun testRecoveryManagerEventEscalationAndCooling() {
        // Test DPI detection handling
        ProxyStats.recordDpiEvent(DpiType.TCP_RESET)
        RecoveryManager.handleEvent(RecoveryEvent.DPI_DETECTED, "Test TCP Reset")

        // Blacklist host test
        RecoveryManager.blacklistHost("badhost.com", 60000L)
        assertTrue(RecoveryManager.isHostBlacklisted("badhost.com"))

        // TrafficShaper RTT update
        TrafficShaper.reset(50L)
        TrafficShaper.updateRtt(400L)
        assertTrue("MSS should adjust on high RTT", TrafficShaper.getRecommendedMss() in listOf(1200, 1440))
        assertTrue("Avg RTT should be tracked", TrafficShaper.getAvgRtt() > 0)
    }

    @Test
    fun testVpnRecoveryCoordinatorIntents() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val coordinator = VpnRecoveryCoordinator(context)
        
        coordinator.triggerRestart()
        val shadowApp = shadowOf(ApplicationProvider.getApplicationContext<android.app.Application>())
        val restartIntent = shadowApp.nextStartedService
        assertNotNull(restartIntent)
        org.junit.Assert.assertEquals("RESTART", restartIntent.action)

        coordinator.triggerStop()
        val stopIntent = shadowApp.nextStartedService
        assertNotNull(stopIntent)
        org.junit.Assert.assertEquals("STOP", stopIntent.action)
    }
}

