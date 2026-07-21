package com.aistudio.pinkproxy.fresh

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

class PinkProxyTileService : TileService() {
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private var listenJob: Job? = null

    override fun onStartListening() {
        super.onStartListening()
        listenJob?.cancel()
        listenJob = scope.launch {
            PinkVpnService.isRunning.collectLatest { running ->
                updateTile(running)
            }
        }
    }

    override fun onStopListening() {
        super.onStopListening()
        listenJob?.cancel()
        listenJob = null
    }

    override fun onDestroy() {
        super.onDestroy()
        try {
            listenJob?.cancel()
            scope.cancel()
        } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
    }

    override fun onClick() {
        super.onClick()
        val isActive = PinkVpnService.isRunning.value
        if (isActive) {
            val intent = Intent(this, PinkVpnService::class.java).apply {
                action = "STOP"
            }
            androidx.core.content.ContextCompat.startForegroundService(this, intent)
        } else {
            val vpnIntent = VpnService.prepare(this)
            if (vpnIntent == null) {
                val intent = Intent(this, PinkVpnService::class.java)
                androidx.core.content.ContextCompat.startForegroundService(this, intent)
            } else {
                // Cannot start directly if permission is not granted
                // Opening the app to handle permission
                val appIntent = Intent(this, MainActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    val pendingIntent = android.app.PendingIntent.getActivity(this, 0, appIntent, android.app.PendingIntent.FLAG_IMMUTABLE)
                    startActivityAndCollapse(pendingIntent)
                } else {
                    @Suppress("DEPRECATION")
                    @android.annotation.SuppressLint("StartActivityAndCollapseDeprecated")
                    startActivityAndCollapse(appIntent)
                }
            }
        }
        updateTile(PinkVpnService.isRunning.value)
    }

    private fun updateTile(isActive: Boolean) {
        val tile = qsTile ?: return
        tile.state = if (isActive) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = "PinkProxy"
        tile.subtitle = if (isActive) "Active" else "Inactive"
        tile.updateTile()
    }
}
