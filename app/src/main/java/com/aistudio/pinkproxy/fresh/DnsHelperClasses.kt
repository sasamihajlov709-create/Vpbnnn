package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import java.net.InetAddress
import java.net.Socket
import javax.net.SocketFactory
import javax.net.ssl.SSLSocketFactory

class ProtectedSocketFactory(private val vpnService: VpnService?) : SocketFactory() {
    companion object {
        fun resolveVpnService(override: VpnService? = null): VpnService? {
            return override ?: BypassConfig.activeVpnService ?: VpnSessionManager.currentSession?.vpnService
        }

        fun createProtectedSocket(vpnService: VpnService? = null): Socket {
            val vpn = resolveVpnService(vpnService)
            val s = Socket()
            if (vpn != null && !vpn.protect(s)) {
                try { s.close() } catch (ignored: Exception) {}
                throw java.io.IOException("VpnService.protect() failed for TCP socket")
            }
            return s
        }

        fun createProtectedDatagramSocket(vpnService: VpnService? = null): java.net.DatagramSocket {
            val vpn = resolveVpnService(vpnService)
            val s = java.net.DatagramSocket()
            if (vpn != null && !vpn.protect(s)) {
                try { s.close() } catch (ignored: Exception) {}
                throw java.io.IOException("VpnService.protect() failed for DatagramSocket")
            }
            return s
        }

        fun protectSocket(s: Socket, vpnService: VpnService? = null): Boolean {
            val vpn = resolveVpnService(vpnService)
            return vpn?.protect(s) ?: true
        }

        fun protectDatagramSocket(s: java.net.DatagramSocket, vpnService: VpnService? = null): Boolean {
            val vpn = resolveVpnService(vpnService)
            return vpn?.protect(s) ?: true
        }
    }

    override fun createSocket(): Socket {
        val s = Socket()
        val vpn = resolveVpnService(vpnService)
        if (vpn != null && !vpn.protect(s)) {
            try { s.close() } catch (ignored: Exception) {}
            throw java.io.IOException("VpnService.protect() failed")
        }
        return s
    }

    override fun createSocket(host: String?, port: Int): Socket =
        createSocket().apply { connect(java.net.InetSocketAddress(host, port)) }

    override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket =
        createSocket().apply {
            if (localHost != null || localPort > 0) {
                bind(java.net.InetSocketAddress(localHost, localPort))
            }
            connect(java.net.InetSocketAddress(host, port))
        }

    override fun createSocket(host: InetAddress?, port: Int): Socket =
        createSocket().apply { connect(java.net.InetSocketAddress(host, port)) }

    override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
        createSocket().apply {
            if (localAddress != null || localPort > 0) {
                bind(java.net.InetSocketAddress(localAddress, localPort))
            }
            connect(java.net.InetSocketAddress(address, port))
        }
}

class ProtectedSSLSocketFactory(private val base: SSLSocketFactory, private val vpnService: VpnService?) : SSLSocketFactory() {
    override fun getDefaultCipherSuites(): Array<String> = base.defaultCipherSuites
    override fun getSupportedCipherSuites(): Array<String> = base.supportedCipherSuites

    override fun createSocket(s: Socket?, host: String?, port: Int, autoClose: Boolean): Socket {
        if (s != null) {
            ProtectedSocketFactory.protectSocket(s, vpnService)
        }
        return base.createSocket(s, host, port, autoClose)
    }

    override fun createSocket(): Socket {
        val s = ProtectedSocketFactory.createProtectedSocket(vpnService)
        return base.createSocket(s, null, 0, true)
    }

    override fun createSocket(host: String?, port: Int): Socket {
        val s = ProtectedSocketFactory.createProtectedSocket(vpnService)
        s.connect(java.net.InetSocketAddress(host, port))
        return base.createSocket(s, host, port, true)
    }

    override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket {
        val s = ProtectedSocketFactory.createProtectedSocket(vpnService)
        if (localHost != null || localPort > 0) {
            s.bind(java.net.InetSocketAddress(localHost, localPort))
        }
        s.connect(java.net.InetSocketAddress(host, port))
        return base.createSocket(s, host, port, true)
    }

    override fun createSocket(host: InetAddress?, port: Int): Socket {
        val s = ProtectedSocketFactory.createProtectedSocket(vpnService)
        s.connect(java.net.InetSocketAddress(host, port))
        return base.createSocket(s, host?.hostAddress ?: "", port, true)
    }

    override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket {
        val s = ProtectedSocketFactory.createProtectedSocket(vpnService)
        if (localAddress != null || localPort > 0) {
            s.bind(java.net.InetSocketAddress(localAddress, localPort))
        }
        s.connect(java.net.InetSocketAddress(address, port))
        return base.createSocket(s, address?.hostAddress ?: "", port, true)
    }
}

class BootstrapDns : okhttp3.Dns {
    private val isResolving = ThreadLocal.withInitial { false }

    override fun lookup(hostname: String): List<InetAddress> {
        if (isResolving.get() == true) {
            return emptyList()
        }

        // Direct IP literal check - zero network overhead, no recursion
        if (DnsCacheManager.isIpAddress(hostname)) {
            return try {
                listOf(InetAddress.getByName(hostname))
            } catch (_: Exception) {
                emptyList()
            }
        }

        val known = mapOf(
            "dns.google" to listOf("8.8.8.8", "8.8.4.4"),
            "dns.google.com" to listOf("8.8.8.8", "8.8.4.4"),
            "cloudflare-dns.com" to listOf("1.1.1.1", "1.0.0.1"),
            "1.1.1.1" to listOf("1.1.1.1"),
            "1.0.0.1" to listOf("1.0.0.1"),
            "dns.quad9.net" to listOf("9.9.9.9", "149.112.112.112"),
            "9.9.9.9" to listOf("9.9.9.9"),
            "dns.adguard.com" to listOf("94.140.14.14", "94.140.15.15"),
            "dns.adguard-dns.com" to listOf("94.140.14.14", "94.140.15.15"),
            "unfiltered.adguard-dns.com" to listOf("94.140.14.140", "94.140.14.141"),
            "dns.controld.com" to listOf("76.76.2.0", "76.76.10.0"),
            "doh.opendns.com" to listOf("208.67.222.222", "208.67.220.220"),
            "doh.mullvad.net" to listOf("194.242.2.2"),
            "dns.sb" to listOf("185.222.222.222", "45.11.45.11"),
            "doh.dns.sb" to listOf("185.222.222.222", "45.11.45.11")
        )
        val lower = hostname.lowercase()
        known[lower]?.let { ips ->
            return ips.mapNotNull { try { InetAddress.getByName(it) } catch (_: Exception) { null } }
        }

        // Cache or fallback without triggering asynchronous re-resolution recursion
        val cached = DnsCacheManager.getCached(lower)
        if (cached != null) return cached

        val emergency = DnsCacheManager.getEmergencyFallback(lower)
        if (emergency != null) return emergency

        isResolving.set(true)
        try {
            // Under active VPN, prevent getaddrinfo from leaking into TUN interface.
            // Attempt a direct protected query via 8.8.8.8 on protected DatagramSocket.
            var datagramSocket: java.net.DatagramSocket? = null
            try {
                datagramSocket = ProtectedSocketFactory.createProtectedDatagramSocket()
                datagramSocket.soTimeout = 2000
                val queryId = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
                val query = DnsPacketEngine.buildDnsQuery(hostname, 1, id = queryId)
                val packet = java.net.DatagramPacket(query, query.size, InetAddress.getByName("8.8.8.8"), 53)
                datagramSocket.send(packet)

                val responseBuf = ByteArray(4096)
                val responsePacket = java.net.DatagramPacket(responseBuf, responseBuf.size)
                datagramSocket.receive(responsePacket)
                val resolved = DnsPacketEngine.parseDnsResponse(responseBuf, responsePacket.length, expectedId = queryId, expectedHost = hostname)
                if (resolved.isNotEmpty()) {
                    DnsCacheManager.put(hostname, resolved)
                    return resolved
                }
            } catch (_: Exception) {
                // Ignore and return emptyList()
            } finally {
                try { datagramSocket?.close() } catch (_: Exception) {}
            }
        } finally {
            isResolving.set(false)
        }

        return emptyList()
    }
}
