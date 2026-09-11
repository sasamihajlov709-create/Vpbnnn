package com.aistudio.pinkproxy.fresh

import android.app.Service
import android.app.NotificationManager
import android.content.Context
import android.content.pm.ServiceInfo
import android.os.Build
import android.util.Log

class VpnNotificationController(private val service: Service) {
    private var lastUpdateMs = 0L

    fun showNotification(status: String = "Engine Active", subtext: String? = "Automated DPI Evasion & Smart Proxy active", isUpdate: Boolean = false) {
        val now = System.currentTimeMillis()
        if (isUpdate && now - lastUpdateMs < 1000) return // Throttle updates to max 1 per second
        
        VpnNotificationManager.createNotificationChannel(service)
        val notification = VpnNotificationManager.buildNotification(service, status, subtext)

        if (isUpdate) {
            try {
                val manager = service.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                manager.notify(1, notification)
                lastUpdateMs = now
            } catch (e: Exception) {
                Log.w("VpnNotificationController", "Failed to update notification: ${e.message}")
            }
            return
        }
        
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                service.startForeground(1, notification)
            } else {
                service.startForeground(1, notification)
            }
            lastUpdateMs = now
        } catch (e: Exception) {
            Log.e("VpnNotificationController", "CRITICAL: startForeground failed: ${e.message}", e)
            throw RuntimeException("Failed to start foreground service", e)
        }
    }

    fun stopNotification() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                service.stopForeground(Service.STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                service.stopForeground(true)
            }
        } catch (e: Exception) {
            Log.v("VpnNotificationController", "Failed to stop foreground notification cleanly: ${e.message}")
        }
    }
}
