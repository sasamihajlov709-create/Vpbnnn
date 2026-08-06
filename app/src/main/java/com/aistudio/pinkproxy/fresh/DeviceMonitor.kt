package com.aistudio.pinkproxy.fresh

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.Build
import android.os.PowerManager
import android.util.Log

object DeviceMonitor {
    private var isMonitoringStarted = false

    fun startDeviceMonitoring(context: Context) {
        if (isMonitoringStarted) return
        isMonitoringStarted = true
        val powerManager = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        
        BypassConfig.isPowerSaveMode = powerManager.isPowerSaveMode

        val batteryStatus: Intent? = IntentFilter(Intent.ACTION_BATTERY_CHANGED).let { filter ->
            context.registerReceiver(null, filter)
        }
        
        batteryStatus?.let { intent ->
            val status = intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
            val charging = status == BatteryManager.BATTERY_STATUS_CHARGING ||
                           status == BatteryManager.BATTERY_STATUS_FULL
            val level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
            val scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
            val batPct = (level * 100 / scale.toFloat()).toInt()
            
            BypassConfig.isCharging = charging
            BypassConfig.batteryLevel = batPct
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try {
                powerManager.addThermalStatusListener { status ->
                    BypassConfig.thermalStatus = status
                    Log.i("DeviceMonitor", "Thermal status changed: $status")
                }
            } catch (e: Throwable) {}
        }

        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_BATTERY_CHANGED)
            addAction(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED)
        }
        
        context.registerReceiver(object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                when (intent.action) {
                    Intent.ACTION_BATTERY_CHANGED -> {
                        val status = intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
                        val charging = status == BatteryManager.BATTERY_STATUS_CHARGING ||
                                       status == BatteryManager.BATTERY_STATUS_FULL
                        val level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
                        val scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
                        val batPct = (level * 100 / scale.toFloat()).toInt()
                        
                        BypassConfig.isCharging = charging
                        BypassConfig.batteryLevel = batPct
                    }
                    PowerManager.ACTION_POWER_SAVE_MODE_CHANGED -> {
                        val active = powerManager.isPowerSaveMode
                        BypassConfig.isPowerSaveMode = active
                        Log.i("DeviceMonitor", "Power save mode: $active")
                    }
                }
            }
        }, filter)
    }
}
