package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import android.util.Log
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.HttpURLConnection
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.HostnameVerifier
import kotlinx.coroutines.*

object DnsProtocols {

    suspend fun queryUdpDns(host: String, dnsIp: String, vpnService: VpnService?): List<InetAddress> {
        val query = DnsPacketEngine.buildDnsQuery(host, 1)
        val socket = DatagramSocket()
        try {
            vpnService?.protect(socket)
            socket.soTimeout = 3000
            val packet = DatagramPacket(query, query.size, InetAddress.getByName(dnsIp), 53)
            socket.send(packet)
            
            val buffer = ByteArray(1024)
            val respPacket = DatagramPacket(buffer, buffer.size)
            socket.receive(respPacket)
            return DnsPacketEngine.parseDnsResponse(respPacket.data, respPacket.length)
        } finally {
            try { socket.close() } catch (e: Exception) {}
        }
    }

    suspend fun queryTcpDns(host: String, dnsIp: String, vpnService: VpnService?): List<InetAddress> {
        val query = DnsPacketEngine.buildDnsQuery(host, 1)
        val socket = Socket()
        try {
            vpnService?.protect(socket)
            socket.connect(InetSocketAddress(dnsIp, 53), 3000)
            socket.soTimeout = 3000
            val dos = DataOutputStream(socket.getOutputStream())
            dos.writeShort(query.size)
            dos.write(query)
            dos.flush()
            
            val dis = DataInputStream(socket.getInputStream())
            val len = dis.readUnsignedShort()
            val resp = ByteArray(len)
            dis.readFully(resp)
            return DnsPacketEngine.parseDnsResponse(resp, len)
        } finally {
            try { socket.close() } catch (e: Exception) {}
        }
    }

    suspend fun queryDoh(host: String, dohUrl: String, vpnService: VpnService?): List<InetAddress> {
        val query = DnsPacketEngine.buildDnsQuery(host, 1)
        var conn: HttpURLConnection? = null
        try {
            val url = java.net.URL(dohUrl)
            conn = url.openConnection(java.net.Proxy.NO_PROXY) as HttpURLConnection
            if (conn is HttpsURLConnection) {
                val sslContext = SSLContext.getInstance("TLS")
                sslContext.init(null, null, null)
                conn.sslSocketFactory = ProtectedSSLSocketFactory(sslContext.socketFactory, vpnService)
                conn.hostnameVerifier = HostnameVerifier { _, _ -> true }
            }
            
            conn.connectTimeout = 4000
            conn.readTimeout = 4000
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/dns-message")
            conn.setRequestProperty("Accept", "application/dns-message")
            
            conn.outputStream.use { it.write(query) }
            
            if (conn.responseCode == 200) {
                val resp = conn.inputStream.use { it.readBytes() }
                return DnsPacketEngine.parseDnsResponse(resp, resp.size)
            }
        } catch (e: Exception) {} finally {
            try { conn?.disconnect() } catch (e: Exception) {}
        }
        return emptyList()
    }

    suspend fun queryDohRacing(host: String, vpnService: VpnService?): List<InetAddress> {
        return kotlinx.coroutines.withTimeoutOrNull(5000) {
            kotlinx.coroutines.supervisorScope {
                val urls = DnsOptimizer.getDohUrls().shuffled().take(4)
                val channel = kotlinx.coroutines.channels.Channel<List<InetAddress>>(urls.size)
                
                urls.forEach { url ->
                    launch(Dispatchers.IO) {
                        val res = queryDoh(host, url, vpnService)
                        if (res.isNotEmpty()) channel.trySend(res)
                    }
                }
                
                val result = try {
                    channel.receive()
                } catch (e: Exception) {
                    emptyList<InetAddress>()
                }
                result
            }
        } ?: emptyList()
    }
}

class ProtectedSSLSocketFactory(private val base: SSLSocketFactory, private val vpnService: VpnService?) : SSLSocketFactory() {
    override fun getDefaultCipherSuites() = base.defaultCipherSuites
    override fun getSupportedCipherSuites() = base.supportedCipherSuites

    override fun createSocket(s: Socket, host: String, port: Int, autoClose: Boolean): Socket {
        return base.createSocket(s, host, port, autoClose)
    }

    override fun createSocket(host: String, port: Int): Socket {
        val s = base.createSocket(host, port)
        vpnService?.protect(s)
        return s
    }

    override fun createSocket(host: String, port: Int, localHost: java.net.InetAddress, localPort: Int): Socket {
        val s = base.createSocket(host, port, localHost, localPort)
        vpnService?.protect(s)
        return s
    }

    override fun createSocket(host: java.net.InetAddress, port: Int): Socket {
        val s = base.createSocket(host, port)
        vpnService?.protect(s)
        return s
    }

    override fun createSocket(address: java.net.InetAddress, port: Int, localAddress: java.net.InetAddress, localPort: Int): Socket {
        val s = base.createSocket(address, port, localAddress, localPort)
        vpnService?.protect(s)
        return s
    }
}
