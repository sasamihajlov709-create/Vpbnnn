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
}
