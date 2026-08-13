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
    private var batteryReceiver: BroadcastReceiver? = null

    fun startDeviceMonitoring(context: Context) {
        if (isMonitoringStarted) return
        isMonitoringStarted = true
        val powerManager = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        
        BypassConfig.isPowerSaveMode = powerManager.isPowerSaveMode
        BypassConfig.isScreenOn = powerManager.isInteractive

        val batteryStatus: Intent? = IntentFilter(Intent.ACTION_BATTERY_CHANGED).let { filter ->
            try {
                context.registerReceiver(null, filter)
            } catch (e: Exception) { null }
        }
        
        batteryStatus?.let { intent ->
            val status = intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
            val charging = status == BatteryManager.BATTERY_STATUS_CHARGING ||
                           status == BatteryManager.BATTERY_STATUS_FULL
            val level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
            val scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
            val batPct = if (scale > 0) (level * 100 / scale.toFloat()).toInt() else 100
            
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
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        }
        
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                when (intent.action) {
                    Intent.ACTION_SCREEN_ON -> {
                        BypassConfig.isScreenOn = true
                        Log.v("DeviceMonitor", "Screen ON: Resuming high-responsiveness mode")
                    }
                    Intent.ACTION_SCREEN_OFF -> {
                        BypassConfig.isScreenOn = false
                        Log.v("DeviceMonitor", "Screen OFF: Entering power-saving deep sleep")
                    }
                    Intent.ACTION_BATTERY_CHANGED -> {
                        val status = intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
                        val charging = status == BatteryManager.BATTERY_STATUS_CHARGING ||
                                       status == BatteryManager.BATTERY_STATUS_FULL
                        val level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
                        val scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
                        val batPct = if (scale > 0) (level * 100 / scale.toFloat()).toInt() else 100
                        
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
        }
        batteryReceiver = receiver
        try {
            context.registerReceiver(receiver, filter)
        } catch (e: Exception) {
            Log.e("DeviceMonitor", "Failed to register battery receiver: ${e.message}")
        }
    }

    fun stopDeviceMonitoring(context: Context) {
        if (!isMonitoringStarted) return
        batteryReceiver?.let {
            try {
                context.unregisterReceiver(it)
            } catch (e: Exception) {
                Log.w("DeviceMonitor", "Unregister battery receiver error: ${e.message}")
            }
        }
        batteryReceiver = null
        isMonitoringStarted = false
    }
}
