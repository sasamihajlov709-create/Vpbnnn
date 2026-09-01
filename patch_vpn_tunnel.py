import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/VpnTunnelManager.kt", "r") as f:
    content = f.read()

new_method = """    private fun hasGlobalIpv6(): Boolean {
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

    fun establish("""

content = content.replace("    fun establish(", new_method)


old_ipv6 = """                    if (tryIpv6) {
                        try {
                            // Assigning a ULA IPv6 address
                            builder.addAddress("fd00::2", 64)
                            builder.addRoute("::", 0)
                            // Note: We removed the hardcoded IPv6 DNS servers to respect user's DNS policy.
                            ipv6SetupSuccessful = true
                        } catch (e: Exception) {
                            Log.w("VpnTunnelManager", "Failed to setup IPv6: ${e.message}")
                            ipv6SetupSuccessful = false
                        }
                    }"""

new_ipv6 = """                    if (tryIpv6) {
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
                    }"""

content = content.replace(old_ipv6, new_ipv6)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/VpnTunnelManager.kt", "w") as f:
    f.write(content)

