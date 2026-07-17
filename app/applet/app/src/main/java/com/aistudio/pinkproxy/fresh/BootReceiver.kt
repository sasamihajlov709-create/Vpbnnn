package com.aistudio.pinkproxy.fresh

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import android.os.Build

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED || intent.action == Intent.ACTION_LOCKED_BOOT_COMPLETED) {
            val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
            val autoConnect = prefs.getBoolean("auto_connect_on_launch", false)
            if (autoConnect) {
                Log.i("BootReceiver", "Auto-starting PinkProxy VPN")
                try {
                    val vpnIntent = Intent(context, PinkVpnService::class.java)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        context.startForegroundService(vpnIntent)
                    } else {
                        context.startService(vpnIntent)
                    }
                } catch (e: Exception) {
                    Log.e("BootReceiver", "Failed to start VPN on boot", e)
                }
            }
        }
    }
}
