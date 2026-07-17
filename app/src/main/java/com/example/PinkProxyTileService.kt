package com.example

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.annotation.RequiresApi

@RequiresApi(Build.VERSION_CODES.N)
class PinkProxyTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        updateTile()
    }

    override fun onClick() {
        super.onClick()
        val isActive = PinkVpnService.isRunning.value
        if (isActive) {
            val intent = Intent(this, PinkVpnService::class.java).apply {
                action = "STOP"
            }
            startService(intent)
        } else {
            val vpnIntent = VpnService.prepare(this)
            if (vpnIntent == null) {
                val intent = Intent(this, PinkVpnService::class.java)
                startForegroundService(intent)
            } else {
                // Cannot start directly if permission is not granted
                // Opening the app to handle permission
                val appIntent = Intent(this, MainActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                startActivityAndCollapse(appIntent)
            }
        }
        updateTile()
    }

    private fun updateTile() {
        val tile = qsTile ?: return
        val isActive = PinkVpnService.isRunning.value
        
        tile.state = if (isActive) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = "PinkProxy"
        tile.updateTile()
    }
}
