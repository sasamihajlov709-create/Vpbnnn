package com.aistudio.pinkproxy.fresh

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED || intent.action == "android.intent.action.QUICKBOOT_POWERON") {
            val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
            val shouldBeRunning = prefs.getBoolean("vpn_was_active", false)
            
            if (shouldBeRunning) {
                Log.i("BootReceiver", "Auto-starting PinkProxy VPN after boot")
                try {
                    val serviceIntent = Intent(context, PinkVpnService::class.java)
                    androidx.core.content.ContextCompat.startForegroundService(context, serviceIntent)
                } catch (e: Exception) {
                    Log.e("BootReceiver", "Failed to start VPN on boot: ${e.message}")
                }
            }
        }
    }
}
