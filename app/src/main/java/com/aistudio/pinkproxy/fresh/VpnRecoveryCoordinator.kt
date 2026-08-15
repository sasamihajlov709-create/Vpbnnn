package com.aistudio.pinkproxy.fresh

import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log

class VpnRecoveryCoordinator(private val context: Context) {

    fun triggerRestart() {
        try {
            ProxyStats.logRecovery("RecoveryCoordinator: Triggering session restart intent")
            val intent = Intent(context, PinkVpnService::class.java).apply {
                action = "RESTART"
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        } catch (e: Exception) {
            Log.e("VpnRecoveryCoordinator", "Failed to send RESTART intent: ${e.message}")
        }
    }

    fun triggerStop() {
        try {
            val intent = Intent(context, PinkVpnService::class.java).apply {
                action = "STOP"
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        } catch (e: Exception) {
            Log.e("VpnRecoveryCoordinator", "Failed to send STOP intent: ${e.message}")
        }
    }
}
