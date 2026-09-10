package com.aistudio.pinkproxy.fresh

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED || intent.action == "android.intent.action.QUICKBOOT_POWERON" || intent.action == "android.intent.action.MY_PACKAGE_REPLACED") {
            Log.i("BootReceiver", "Device booted. PinkProxy relies on Android's built-in Always-on VPN feature for auto-start. Custom background service start is disabled for Android 14+ compatibility.")
        }
    }
}
