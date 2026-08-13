package com.aistudio.pinkproxy.fresh

data class NetworkProfile(
    val id: String,
    val type: NetworkType,
    val displayName: String,
    val carrierOrGateway: String = "",
    val timestamp: Long = System.currentTimeMillis()
) {
    companion object {
        val DEFAULT_WIFI = NetworkProfile(
            id = "wifi_default",
            type = NetworkType.WIFI,
            displayName = "Wi-Fi (Default)"
        )
        val DEFAULT_MOBILE = NetworkProfile(
            id = "mobile_default",
            type = NetworkType.MOBILE,
            displayName = "Cellular (Default)"
        )
        val DEFAULT_ETHERNET = NetworkProfile(
            id = "ethernet_default",
            type = NetworkType.ETHERNET,
            displayName = "Ethernet"
        )
        val UNKNOWN = NetworkProfile(
            id = "unknown_default",
            type = NetworkType.UNKNOWN,
            displayName = "Unknown Network"
        )
    }
}
