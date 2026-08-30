package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import java.net.InetAddress
import java.net.Socket
import javax.net.SocketFactory
import javax.net.ssl.SSLSocketFactory

class ProtectedSocketFactory(private val vpnService: VpnService?) : SocketFactory() {
    override fun createSocket(): Socket {
        val s = Socket();
        if (vpnService?.protect(s) == false) throw java.io.IOException("protect failed")
        return s
    }
    override fun createSocket(host: String?, port: Int): Socket = createSocket().apply { connect(java.net.InetSocketAddress(host, port)) }
    override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket = createSocket()
    override fun createSocket(host: InetAddress?, port: Int): Socket = createSocket()
    override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket = createSocket()
}

class ProtectedSSLSocketFactory(private val base: SSLSocketFactory, private val vpnService: VpnService?) : SSLSocketFactory() {
    override fun getDefaultCipherSuites(): Array<String> = base.defaultCipherSuites
    override fun getSupportedCipherSuites(): Array<String> = base.supportedCipherSuites
    override fun createSocket(s: Socket?, host: String?, port: Int, autoClose: Boolean): Socket = base.createSocket(s, host, port, autoClose)
    override fun createSocket(): Socket {
        val s = Socket();
        if (vpnService?.protect(s) == false) throw java.io.IOException("protect failed")
        return base.createSocket(s, null, 0, true)
    }
    override fun createSocket(host: String?, port: Int): Socket = base.createSocket(createSocket(), host, port, true)
    override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket = base.createSocket(createSocket(), host, port, true)
    override fun createSocket(host: InetAddress?, port: Int): Socket = base.createSocket(createSocket(), host?.hostAddress ?: "", port, true)
    override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket = base.createSocket(createSocket(), address?.hostAddress ?: "", port, true)
}

class BootstrapDns : okhttp3.Dns {
    override fun lookup(hostname: String): List<InetAddress> {
        val known = mapOf(
            "dns.google" to listOf("8.8.8.8", "8.8.4.4"),
            "dns.google.com" to listOf("8.8.8.8", "8.8.4.4"),
            "cloudflare-dns.com" to listOf("1.1.1.1", "1.0.0.1"),
            "1.1.1.1" to listOf("1.1.1.1"),
            "dns.quad9.net" to listOf("9.9.9.9", "149.112.112.112"),
            "9.9.9.9" to listOf("9.9.9.9"),
            "dns.adguard.com" to listOf("94.140.14.14", "94.140.15.15"),
            "dns.adguard-dns.com" to listOf("94.140.14.14", "94.140.15.15"),
            "unfiltered.adguard-dns.com" to listOf("94.140.14.140", "94.140.14.141"),
            "dns.controld.com" to listOf("76.76.2.0", "76.76.10.0"),
            "doh.opendns.com" to listOf("208.67.222.222", "208.67.220.220"),
            "doh.mullvad.net" to listOf("194.242.2.2")
        )
        known[hostname.lowercase()]?.let { ips -> return ips.mapNotNull { try { InetAddress.getByName(it) } catch (e: Exception) { null } } }
        return try {
            DnsCacheManager.getCached(hostname) ?: InetAddress.getAllByName(hostname).toList()
        } catch (e: Exception) {
            emptyList()
        }
    }
}
