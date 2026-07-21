package com.aistudio.pinkproxy.fresh

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import androidx.core.app.NotificationCompat
import android.net.VpnService

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (Intent.ACTION_BOOT_COMPLETED == intent.action || Intent.ACTION_MY_PACKAGE_REPLACED == intent.action || "android.intent.action.QUICKBOOT_POWERON" == intent.action) {
            Log.i("BootReceiver", "PinkProxy received BOOT_COMPLETED. Checking if VPN should restart...")
            val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
            val vpnWasActive = prefs.getBoolean("vpn_was_active", false)
            val autoStartOnBoot = prefs.getBoolean("auto_start_on_boot", true)
            
            if (vpnWasActive && autoStartOnBoot) {
                Log.i("BootReceiver", "Restarting PinkProxy VPN service after boot.")
                val serviceIntent = Intent(context, PinkVpnService::class.java).apply {
                    action = "START"
                }
                
                try {
                    // If VpnService.prepare returns null, the VPN is already authorized by the user.
                    // We can directly use startService for VpnService, as it's a system-bound service 
                    // and typically exempt from background start restrictions if authorized.
                    if (VpnService.prepare(context) == null) {
                        androidx.core.content.ContextCompat.startForegroundService(context, serviceIntent)
                    } else {
                        // Needs user permission again, show notification
                        Log.w("BootReceiver", "VPN permission revoked. User must launch manually.")
                        postFallbackNotification(context)
                    }
                } catch (e: Exception) {
                    Log.e("BootReceiver", "Failed to start VPN service on boot", e)
                    postFallbackNotification(context)
                }
            }
        }
    }

    private fun postFallbackNotification(context: Context) {
        try {
            val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            
            // Re-create channel just in case it doesn't exist yet (boot completed)
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                val channel = NotificationChannel(
                    "pink_proxy_channel",
                    "PinkProxy Service Channel",
                    NotificationManager.IMPORTANCE_HIGH
                )
                notificationManager.createNotificationChannel(channel)
            }

            val launchIntent = Intent(context, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            }
            val pendingIntent = PendingIntent.getActivity(
                context,
                101,
                launchIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )

            val notification = NotificationCompat.Builder(context, "pink_proxy_channel")
                .setContentTitle("PinkProxy Автозапуск")
                .setContentText("Нажмите для активации VPN-соединения после перезагрузки")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .build()

            notificationManager.notify(101, notification)
        } catch (e: Exception) {
            Log.e("BootReceiver", "Failed to send fallback notification", e)
        }
    }
}
