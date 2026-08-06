package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import java.net.InetAddress
import java.net.Socket
import javax.net.SocketFactory
import javax.net.ssl.SSLSocketFactory

class ProtectedSocketFactory(private val vpnService: VpnService?) : SocketFactory() {
    override fun createSocket(): Socket {
        val s = Socket()
        try { vpnService?.protect(s) } catch (e: Throwable) {}
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
        val s = Socket()
        try { vpnService?.protect(s) } catch (e: Throwable) {}
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
            "cloudflare-dns.com" to listOf("1.1.1.1", "1.0.0.1"),
            "dns.quad9.net" to listOf("9.9.9.9", "149.112.112.112"),
            "dns.adguard.com" to listOf("94.140.14.14", "94.140.15.15"),
            "dns.controld.com" to listOf("76.76.2.0", "76.76.10.0")
        )
        known[hostname]?.let { ips -> return ips.map { InetAddress.getByName(it) } }
        return try {
            DnsCacheManager.getCached(hostname) ?: InetAddress.getAllByName(hostname).toList()
        } catch (e: Throwable) {
            emptyList()
        }
    }
}
