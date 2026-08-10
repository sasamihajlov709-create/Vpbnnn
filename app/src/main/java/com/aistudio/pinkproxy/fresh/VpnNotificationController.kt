package com.aistudio.pinkproxy.fresh

import android.app.Service
import android.content.pm.ServiceInfo
import android.os.Build
import android.util.Log

class VpnNotificationController(private val service: Service) {

    fun showNotification(status: String = "Engine Active", subtext: String? = "Automated DPI Evasion & Smart Proxy active") {
        VpnNotificationManager.createNotificationChannel(service)
        val notification = VpnNotificationManager.buildNotification(service, status, subtext)

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                try {
                    service.startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
                } catch (e: Exception) {
                    Log.w("VpnNotificationController", "Failed specialUse foreground start: ${e.message}, falling back to standard foreground")
                    service.startForeground(1, notification)
                }
            } else {
                service.startForeground(1, notification)
            }
        } catch (e: Exception) {
            Log.e("VpnNotificationController", "startForeground failed: ${e.message}", e)
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
