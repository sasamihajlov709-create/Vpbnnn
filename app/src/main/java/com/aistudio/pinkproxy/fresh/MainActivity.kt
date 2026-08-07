package com.aistudio.pinkproxy.fresh

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.*
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aistudio.pinkproxy.fresh.ui.PinkProxyApp
import com.aistudio.pinkproxy.fresh.ui.theme.MyApplicationTheme
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings

class MainActivity : ComponentActivity() {
    private val vpnLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK || android.net.VpnService.prepare(this) == null) {
            startVpnService()
        } else {
            android.widget.Toast.makeText(this, "VPN permission is required to run", android.widget.Toast.LENGTH_LONG).show()
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(ActivityResultContracts.RequestPermission()) { isGranted ->
        if (isGranted) {
            Log.d("MainActivity", "Notification permission granted")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        enableEdgeToEdge()
        
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            if (androidx.core.content.ContextCompat.checkSelfPermission(this, android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                notificationPermissionLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
            }
        }
        
        try {
            PinkVpnService.loadFilterSettings(this)
            BypassConfig.loadTuningSettings(this)
            RobustResolver.loadDnsSettings(this)
        } catch (e: Throwable) {
            Log.e("MainActivity", "Error loading initial settings", e)
        }
        
        requestIgnoreBatteryOptimizations()
        
        val prefs = getSharedPreferences("pink_proxy_settings", MODE_PRIVATE)
        val autoConnect = prefs.getBoolean("auto_connect_on_launch", false)
        
        setContent {
            val vpnState by VpnRuntimeState.lifecycleState.collectAsStateWithLifecycle()
            val vpnError by VpnRuntimeState.lastError.collectAsStateWithLifecycle()
            val isVpnActive = vpnState == VpnLifecycleState.RUNNING || vpnState == VpnLifecycleState.RECOVERING
            
            LaunchedEffect(Unit) {
                if (autoConnect && vpnState == VpnLifecycleState.IDLE) {
                    toggleVpn(false) 
                }
            }

            MyApplicationTheme(dynamicColor = false) {
                PinkProxyApp(
                    vpnState = vpnState,
                    vpnError = vpnError,
                    onToggle = { toggleVpn(isVpnActive) },
                    onRestart = { 
                        if (isVpnActive) {
                            try {
                                val intent = Intent(this@MainActivity, PinkVpnService::class.java).apply {
                                    action = "RESTART"
                                }
                                androidx.core.content.ContextCompat.startForegroundService(this@MainActivity, intent)
                            } catch (e: Throwable) {
                                Log.e("MainActivity", "Quick restart failed: ${e.message}")
                            }
                        }
                    },
                    onDismissError = { VpnRuntimeState.clearError() }
                )
            }
        }
    }

    private fun toggleVpn(isActive: Boolean) {
        if (isActive) {
            stopVpnService()
        } else {
            try {
                val vpnIntent = VpnService.prepare(this)
                if (vpnIntent != null) {
                    vpnLauncher.launch(vpnIntent)
                } else {
                    startVpnService()
                }
            } catch (e: SecurityException) {
                Log.e("MainActivity", "VPN preparation failed", e)
                android.widget.Toast.makeText(
                    this,
                    "Security Error: Please restart the app or check VPN permissions.",
                    android.widget.Toast.LENGTH_LONG
                ).show()
            }
        }
    }

    @SuppressLint("BatteryLife")
    private fun requestIgnoreBatteryOptimizations() {
        try {
            val packageName = packageName
            val pm = getSystemService(POWER_SERVICE) as PowerManager
            if (!pm.isIgnoringBatteryOptimizations(packageName)) {
                val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = Uri.parse("package:$packageName")
                }
                startActivity(intent)
            }
        } catch (e: Throwable) {
            Log.e("MainActivity", "Failed to request battery optimization exemption", e)
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, PinkVpnService::class.java)
        try {
            androidx.core.content.ContextCompat.startForegroundService(this, intent)
        } catch (e: Throwable) {
            Log.e("MainActivity", "Failed to start VPN service: ${e.message}")
        }
    }

    private fun stopVpnService() {
        val intent = Intent(this, PinkVpnService::class.java).apply {
            action = "STOP"
        }
        try {
            androidx.core.content.ContextCompat.startForegroundService(this, intent)
        } catch (e: Throwable) {
            Log.e("MainActivity", "Failed to stop VPN service: ${e.message}")
        }
    }
}
