package com.aistudio.pinkproxy.fresh

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED || 
            intent.action == "android.intent.action.QUICKBOOT_POWERON") {
            
            val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
            val shouldAutoStart = prefs.getBoolean("vpn_should_be_running", false) || 
                                 prefs.getBoolean("vpn_was_active", false) || prefs.getBoolean("auto_connect_on_launch", true)
            
            if (shouldAutoStart) {
                Log.d("BootReceiver", "Starting PinkProxyService after boot (sticky state)")
                val vpnIntent = VpnService.prepare(context)
                if (vpnIntent == null) {
                    try {
                        val serviceIntent = Intent(context, PinkVpnService::class.java)
                        context.startForegroundService(serviceIntent)
                    } catch (e: Exception) {
                        Log.e("BootReceiver", "Failed to start service from background: ${e.message}")
                    }
                } else {
                    Log.w("BootReceiver", "VPN preparation required, cannot auto-start service")
                }
            }
        }
    }
}
