package com.aistudio.pinkproxy.fresh

import android.net.VpnService

fun startTun2Socks(vpnInterface: android.os.ParcelFileDescriptor, proxyPort: Int) {
    try {
        engine.Engine.touch()
        val key = engine.Key()
        key.setProxy("socks5://127.0.0.1:$proxyPort")
        key.setDevice("fd://${vpnInterface.fd}")
        key.setLogLevel("info")
        engine.Engine.insert(key)
        engine.Engine.start()
        android.util.Log.i("PinkVpnService", "tun2socks started successfully on fd ${vpnInterface.fd}")
    } catch (e: Exception) {
        android.util.Log.e("PinkVpnService", "Failed to start tun2socks", e)
    }
}

fun stopTun2Socks() {
    try {
        engine.Engine.stop()
        android.util.Log.i("PinkVpnService", "tun2socks stopped")
    } catch (e: Exception) {
        android.util.Log.e("PinkVpnService", "Failed to stop tun2socks", e)
    }
}
