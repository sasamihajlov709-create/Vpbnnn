package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.IOException
import java.net.InetAddress

class VpnTunnelManager(private val service: VpnService) {
    private var vpnInterface: ParcelFileDescriptor? = null

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
        val builder = service.Builder()
            .setSession(sessionName)
            .setMtu(mtu)
            .addAddress(addressV4, prefixV4)
            .addRoute("0.0.0.0", 0)
            .setBlocking(isBlocking)

        dnsServers.forEach { dns ->
            try {
                builder.addDnsServer(dns)
            } catch (e: Exception) {
                Log.e("VpnTunnelManager", "Failed to add DNS server $dns: ${e.message}")
            }
        }

        if (includeIpv6) {
            try {
                builder.addAddress("fd00::2", 64)
                builder.addRoute("::", 0)
                builder.addDnsServer("2606:4700:4700::1111")
                builder.addDnsServer("2001:4860:4860::8888")
            } catch (e: Exception) {
                Log.w("VpnTunnelManager", "Failed to add IPv6 route/DNS: ${e.message}")
            }
        }

        if (isExcludeMode) {
            builder.addDisallowedApplication(appPackageName)
            selectedPackages.forEach { pkg ->
                try {
                    builder.addDisallowedApplication(pkg)
                } catch (e: Exception) {
                    Log.v("VpnTunnelManager", "Ignored disallowed app: $pkg")
                }
            }
        } else {
            selectedPackages.filter { it != appPackageName }.forEach { pkg ->
                try {
                    builder.addAllowedApplication(pkg)
                } catch (e: Exception) {
                    Log.v("VpnTunnelManager", "Ignored allowed app: $pkg")
                }
            }
        }

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        try {
            vpnInterface = builder.establish()
            Log.i("VpnTunnelManager", "TUN Interface established: $vpnInterface")
            return vpnInterface
        } catch (e: Exception) {
            Log.e("VpnTunnelManager", "Failed to establish TUN interface: ${e.message}")
            return null
        }
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
