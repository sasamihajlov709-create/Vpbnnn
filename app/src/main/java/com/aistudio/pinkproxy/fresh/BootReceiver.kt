package com.aistudio.pinkproxy.fresh

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED || intent.action == "android.intent.action.QUICKBOOT_POWERON" || intent.action == "android.intent.action.MY_PACKAGE_REPLACED") {
            val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
            val shouldBeRunning = prefs.getBoolean("vpn_was_active", false)
            
            if (shouldBeRunning) {
                Log.i("BootReceiver", "Auto-starting PinkProxy VPN after boot")
                try {
                    val vpnIntent = VpnService.prepare(context)
                    if (vpnIntent == null) {
                        val serviceIntent = Intent(context, PinkVpnService::class.java)
                        ContextCompat.startForegroundService(context, serviceIntent)
                    } else {
                        Log.w("BootReceiver", "VPN permission was revoked, cannot auto-start.")
                        prefs.edit().putBoolean("vpn_was_active", false).apply()
                    }
                } catch (e: Exception) {
                    Log.e("BootReceiver", "Failed to auto-start VPN on boot: ${e.message}")
                }
            }
        }
    }
}
