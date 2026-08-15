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
    private val activeNetworks = java.util.concurrent.ConcurrentHashMap<Network, NetworkType>()
    private val networkCapabilitiesMap = java.util.concurrent.ConcurrentHashMap<Network, NetworkCapabilities>()

    fun start() {
        if (networkCallback != null) return

        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val capabilities = connectivityManager.getNetworkCapabilities(network)
                val type = getNetworkType(capabilities)
                activeNetworks[network] = type
                if (capabilities != null) {
                    networkCapabilitiesMap[network] = capabilities
                }
                val defaultNet = connectivityManager.activeNetwork
                if (defaultNet == null || defaultNet == network) {
                    NetworkProfileManager.updateNetwork(context, network)
                    Log.i("VpnNetworkMonitor", "Network available: $network (Type: $type, Profile: ${NetworkProfileManager.currentProfile.value.displayName})")
                    networkChangeCallback(network, type)
                } else {
                    Log.d("VpnNetworkMonitor", "Secondary network available: $network (Type: $type) - skipping global profile change")
                }
            }

            override fun onLost(network: Network) {
                activeNetworks.remove(network)
                networkCapabilitiesMap.remove(network)
                Log.i("VpnNetworkMonitor", "Network lost: $network")
                val systemActiveNet = connectivityManager.activeNetwork
                if (systemActiveNet != null) {
                    val type = activeNetworks[systemActiveNet] ?: run {
                        val caps = connectivityManager.getNetworkCapabilities(systemActiveNet)
                        val t = getNetworkType(caps)
                        activeNetworks[systemActiveNet] = t
                        t
                    }
                    NetworkProfileManager.updateNetwork(context, systemActiveNet)
                    networkChangeCallback(systemActiveNet, type)
                } else {
                    NetworkProfileManager.updateNetwork(context, null)
                    networkChangeCallback(null, NetworkType.NONE)
                }
            }

            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                val newType = getNetworkType(capabilities)
                activeNetworks[network] = newType
                val defaultNet = connectivityManager.activeNetwork
                if (defaultNet == null || defaultNet == network) {
                    NetworkProfileManager.updateNetwork(context, network)
                }
                val oldCaps = networkCapabilitiesMap[network]
                if (oldCaps != null) {
                    val transportsChanged = !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) && oldCaps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                                           capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) && !oldCaps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                                           !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) && oldCaps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
                                           capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) && !oldCaps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
                    
                    val validationChanged = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) != oldCaps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                    
                    if (!transportsChanged && !validationChanged) return
                }
                networkCapabilitiesMap[network] = capabilities
                capabilitiesChangeCallback(network, capabilities)
            }
        }

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
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
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> {
                // If downlink bandwidth is very constrained (< 1500 kbps) or unmetered is false with low link speed
                val downKbps = capabilities.linkDownstreamBandwidthKbps
                if (downKbps in 1..1500) {
                    NetworkType.MOBILE_LOW
                } else {
                    NetworkType.MOBILE
                }
            }
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
