package com.aistudio.pinkproxy.fresh

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.telephony.TelephonyManager
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.security.MessageDigest
import java.util.concurrent.CopyOnWriteArrayList

object NetworkProfileManager {
    private val _currentProfile = MutableStateFlow(NetworkProfile.UNKNOWN)
    val currentProfile: StateFlow<NetworkProfile> = _currentProfile.asStateFlow()

    private val profileChangeListeners = CopyOnWriteArrayList<(oldProfile: NetworkProfile, newProfile: NetworkProfile) -> Unit>()

    fun addListener(listener: (oldProfile: NetworkProfile, newProfile: NetworkProfile) -> Unit) {
        if (!profileChangeListeners.contains(listener)) {
            profileChangeListeners.add(listener)
        }
    }

    fun removeListener(listener: (oldProfile: NetworkProfile, newProfile: NetworkProfile) -> Unit) {
        profileChangeListeners.remove(listener)
    }

    fun updateNetwork(context: Context, network: Network?) {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        val targetNet = network ?: cm.activeNetwork
        if (targetNet == null) {
            setCurrentProfile(NetworkProfile.UNKNOWN)
            return
        }

        val capabilities = cm.getNetworkCapabilities(targetNet)
        val linkProperties = cm.getLinkProperties(targetNet)
        val newProfile = detectProfile(context, targetNet, capabilities, linkProperties)
        setCurrentProfile(newProfile)
    }

    fun detectProfile(
        context: Context,
        network: Network?,
        capabilities: NetworkCapabilities?,
        linkProperties: LinkProperties?
    ): NetworkProfile {
        if (capabilities == null) {
            return NetworkProfile.UNKNOWN
        }

        return when {
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> {
                buildWifiProfile(linkProperties)
            }
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> {
                buildCellularProfile(context)
            }
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> {
                NetworkProfile.DEFAULT_ETHERNET
            }
            else -> {
                NetworkProfile(
                    id = "other_net",
                    type = NetworkType.OTHER,
                    displayName = "Other Network"
                )
            }
        }
    }

    private fun buildWifiProfile(linkProperties: LinkProperties?): NetworkProfile {
        val dnsList = linkProperties?.dnsServers?.map { it.hostAddress } ?: emptyList()
        val routes = linkProperties?.routes?.mapNotNull { it.gateway?.hostAddress } ?: emptyList()
        val iface = linkProperties?.interfaceName ?: "wlan0"

        val fingerprintData = if (routes.isNotEmpty() || dnsList.isNotEmpty()) {
            "wifi:${routes.sorted().joinToString(",")};dns:${dnsList.sorted().joinToString(",")}"
        } else {
            "wifi:iface:$iface"
        }

        val hash = hashSignature(fingerprintData).take(8)
        val gateway = routes.firstOrNull() ?: dnsList.firstOrNull() ?: ""
        val displayName = if (gateway.isNotEmpty()) "Wi-Fi ($gateway)" else "Wi-Fi (Home/Office)"

        return NetworkProfile(
            id = "wifi_$hash",
            type = NetworkType.WIFI,
            displayName = displayName,
            carrierOrGateway = gateway
        )
    }

    private fun buildCellularProfile(context: Context): NetworkProfile {
        var operatorCode = ""
        var operatorName = ""

        try {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            if (tm != null) {
                operatorCode = tm.simOperator.ifEmpty { tm.networkOperator }
                operatorName = tm.simOperatorName.ifEmpty { tm.networkOperatorName }
            }
        } catch (e: Exception) {
            Log.v("NetworkProfileManager", "Failed to query TelephonyManager: ${e.message}")
        }

        val resolvedName = when {
            operatorName.isNotBlank() -> operatorName
            operatorCode == "25001" -> "MTS"
            operatorCode == "25002" -> "MegaFon"
            operatorCode == "25099" -> "Beeline"
            operatorCode == "25020" -> "Tele2 / T-Mobile"
            operatorCode == "25004" -> "Motiv"
            operatorCode == "25011" -> "Yota"
            operatorCode == "25028" -> "Beeline"
            operatorCode == "25039" -> "Rostelecom"
            operatorCode.isNotBlank() -> "Carrier $operatorCode"
            else -> "Mobile Data"
        }

        val idKey = if (operatorCode.isNotBlank()) "cell_$operatorCode" else "cell_${hashSignature(resolvedName).take(6)}"

        return NetworkProfile(
            id = idKey,
            type = NetworkType.MOBILE,
            displayName = "Cellular ($resolvedName)",
            carrierOrGateway = resolvedName
        )
    }

    fun setProfileForTesting(profile: NetworkProfile) {
        setCurrentProfile(profile)
    }

    private fun setCurrentProfile(newProfile: NetworkProfile) {
        val oldProfile = _currentProfile.value
        if (oldProfile.id != newProfile.id) {
            Log.i("NetworkProfileManager", "Network profile switch: ${oldProfile.displayName} -> ${newProfile.displayName} (ID: ${newProfile.id})")
            _currentProfile.value = newProfile
            profileChangeListeners.forEach { listener ->
                try {
                    listener(oldProfile, newProfile)
                } catch (e: Exception) {
                    Log.e("NetworkProfileManager", "Listener error on profile switch: ${e.message}", e)
                }
            }
        }
    }

    private fun hashSignature(input: String): String {
        return try {
            val md = MessageDigest.getInstance("MD5")
            val bytes = md.digest(input.toByteArray(Charsets.UTF_8))
            bytes.joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            input.hashCode().toString(16)
        }
    }
}
