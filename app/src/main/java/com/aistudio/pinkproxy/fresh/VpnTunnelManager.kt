package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.IOException
import java.net.InetAddress

class VpnTunnelManager(private val service: VpnService) {
    private var vpnInterface: ParcelFileDescriptor? = null
    var isIpv6Active: Boolean = false
        private set

    private fun hasGlobalIpv6(): Boolean {
        try {
            val interfaces = java.net.NetworkInterface.getNetworkInterfaces()
            while (interfaces.hasMoreElements()) {
                val iface = interfaces.nextElement()
                if (iface.isUp && !iface.isLoopback) {
                    val addresses = iface.inetAddresses
                    while (addresses.hasMoreElements()) {
                        val addr = addresses.nextElement()
                        if (addr is java.net.Inet6Address) {
                            if (!addr.isLinkLocalAddress && !addr.isLoopbackAddress && !addr.isSiteLocalAddress) {
                                return true
                            }
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.e("VpnTunnelManager", "Error checking for IPv6", e)
        }
        return false
    }

    fun establish(
        sessionName: String,
        mtu: Int,
        addressV4: String,
        prefixV4: Int,
        dnsServers: List<String>,
        includeIpv6: Boolean,
        isExcludeMode: Boolean,
        selectedPackages: Set<String>,
        appPackageName: String,
        allowBypass: Boolean = false,
        isBlocking: Boolean = true
    ): ParcelFileDescriptor? {
        val candidates = listOf(
            Pair(addressV4, if (prefixV4 == 24) 32 else prefixV4),
            Pair("10.233.233.2", 32),
            Pair("172.19.0.1", 30),
            Pair("10.0.0.2", 32),
            Pair("192.168.250.1", 32)
        ).distinct()

        val ipv6Options = if (includeIpv6) listOf(true, false) else listOf(false)

        for (tryIpv6 in ipv6Options) {
            for ((addr, prefix) in candidates) {
                var ipv6SetupSuccessful = false
                try {
                    val builder = service.Builder()
                        .setSession(sessionName)
                        .setMtu(mtu.coerceIn(1200, 1500))
                        .addAddress(addr, prefix)
                        .addRoute("0.0.0.0", 0)
                        .setBlocking(isBlocking)

                    if (allowBypass) {
                        try { builder.allowBypass() } catch (e: Exception) { Log.w("VpnTunnelManager", "allowBypass error: ${e.message}") }
                    }

                    dnsServers.forEach { dns ->
                        try {
                            builder.addDnsServer(dns)
                        } catch (e: Exception) {
                            Log.w("VpnTunnelManager", "Failed to add DNS server $dns: ${e.message}")
                        }
                    }

                    if (tryIpv6) {
                        try {
                            if (hasGlobalIpv6()) {
                                // Assigning a ULA IPv6 address
                                builder.addAddress("fd00::2", 64)
                                builder.addRoute("::", 0)
                                // Note: We removed the hardcoded IPv6 DNS servers to respect user's DNS policy.
                                ipv6SetupSuccessful = true
                            } else {
                                Log.i("VpnTunnelManager", "No global IPv6 detected on network; bypassing IPv6 routes.")
                                ipv6SetupSuccessful = false
                            }
                        } catch (e: Exception) {
                            Log.w("VpnTunnelManager", "Failed to setup IPv6: ${e.message}")
                            ipv6SetupSuccessful = false
                        }
                    }

                    if (isExcludeMode) {
                        try { builder.addDisallowedApplication(appPackageName) } catch (_: Exception) {}
                        selectedPackages.forEach { pkg ->
                            try { builder.addDisallowedApplication(pkg) } catch (_: Exception) {}
                        }
                    } else {
                        selectedPackages.filter { it != appPackageName }.forEach { pkg ->
                            try { builder.addAllowedApplication(pkg) } catch (_: Exception) {}
                        }
                    }

                    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                        try { builder.setMetered(false) } catch (_: Exception) {}
                    }

                    val descriptor = builder.establish()
                    if (descriptor != null) {
                        vpnInterface = descriptor
                        isIpv6Active = tryIpv6 && ipv6SetupSuccessful
                        Log.i("VpnTunnelManager", "TUN Interface established with addr=$addr/$prefix, ipv6=$isIpv6Active: $descriptor")
                        return descriptor
                    }
                } catch (e: Exception) {
                    Log.w("VpnTunnelManager", "Establish attempt failed (addr=$addr/$prefix, ipv6=$tryIpv6): ${e.message}")
                }
            }
        }

        isIpv6Active = false
        Log.e("VpnTunnelManager", "Failed to establish TUN interface with all address candidates.")
        return null
    }

    fun getDescriptor(): ParcelFileDescriptor? = vpnInterface

    fun close() {
        try {
            vpnInterface?.close()
            Log.i("VpnTunnelManager", "TUN Interface closed")
        } catch (e: IOException) {
            Log.e("VpnTunnelManager", "Error closing TUN interface: ${e.message}")
        } finally {
            vpnInterface = null
        }
    }

    fun isEstablished(): Boolean = vpnInterface != null
}
