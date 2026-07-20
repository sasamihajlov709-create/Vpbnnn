package com.aistudio.pinkproxy.fresh

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (Intent.ACTION_BOOT_COMPLETED == intent.action) {
            Log.i("BootReceiver", "PinkProxy received BOOT_COMPLETED. Checking if VPN should restart...")
            val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
            val vpnWasActive = prefs.getBoolean("vpn_was_active", false)
            val autoStartOnBoot = prefs.getBoolean("auto_start_on_boot", true)
            
            if (vpnWasActive && autoStartOnBoot) {
                Log.i("BootReceiver", "Restarting PinkProxy VPN service after boot.")
                val serviceIntent = Intent(context, PinkVpnService::class.java).apply {
                    action = "START"
                }
                if (android.os.Build.VERSION.SDK_INT >= 31) {
                    try {
                        context.startForegroundService(serviceIntent)
                    } catch (e: android.app.ForegroundServiceStartNotAllowedException) {
                        Log.e("BootReceiver", "Foreground service start not allowed (Android 12+ limitation). User must launch manually.", e)
                    } catch (e: Exception) {
                        Log.e("BootReceiver", "Failed to start foreground service on boot", e)
                    }
                } else {
                    context.startService(serviceIntent)
                }
            }
        }
    }
}
