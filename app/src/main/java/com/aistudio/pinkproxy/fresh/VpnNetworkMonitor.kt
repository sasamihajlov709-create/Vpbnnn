package com.aistudio.pinkproxy.fresh

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log

class VpnNetworkMonitor(
    private val context: Context,
    private val networkChangeCallback: (Network?, NetworkType) -> Unit,
    private val capabilitiesChangeCallback: (Network, NetworkCapabilities) -> Unit
) {
    private val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    fun start() {
        if (networkCallback != null) return

        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val capabilities = connectivityManager.getNetworkCapabilities(network)
                val type = getNetworkType(capabilities)
                Log.i("VpnNetworkMonitor", "Network available: $network (Type: $type)")
                networkChangeCallback(network, type)
            }

            override fun onLost(network: Network) {
                Log.i("VpnNetworkMonitor", "Network lost: $network")
                networkChangeCallback(null, NetworkType.NONE)
            }

            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                capabilitiesChangeCallback(network, capabilities)
            }
        }

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        
        try {
            connectivityManager.registerNetworkCallback(request, networkCallback!!)
        } catch (e: Exception) {
            Log.e("VpnNetworkMonitor", "Failed to register network callback: ${e.message}")
        }
    }

    private fun getNetworkType(capabilities: NetworkCapabilities?): NetworkType {
        if (capabilities == null) return NetworkType.NONE
        return when {
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetworkType.WIFI
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetworkType.MOBILE
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> NetworkType.ETHERNET
            else -> NetworkType.OTHER
        }
    }

    fun stop() {
        networkCallback?.let {
            try {
                connectivityManager.unregisterNetworkCallback(it)
            } catch (e: Exception) {
                Log.e("VpnNetworkMonitor", "Failed to unregister network callback: ${e.message}")
            }
            networkCallback = null
        }
    }
}
