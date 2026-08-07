package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import java.net.InetAddress

object UdpDnsProtocols {
    suspend fun queryDnsOverQuic(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = emptyList()
    suspend fun queryUdpDnsDetailed(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<DnsPacketEngine.DnsRecord> = emptyList()
    suspend fun queryUdpDnsReorder(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = emptyList()
    suspend fun queryUdpDns(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = emptyList()
    suspend fun queryUdpDnsNuclear(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = emptyList()
    suspend fun queryUdpDnsShadow(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = emptyList()
}

object TcpDnsProtocols {
    suspend fun queryTcpDnsShadow(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = emptyList()
    suspend fun queryTcpDnsNuclear(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = emptyList()
    suspend fun queryTcpDns(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = emptyList()
    suspend fun queryDnsOverTcp(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = emptyList()
}

object DohDnsProtocols {
    suspend fun queryDohDetailed(host: String, dohUrl: String, vpnService: VpnService?, type: Int): List<DnsPacketEngine.DnsRecord> = emptyList()
    suspend fun queryDoh(host: String, dohUrl: String, vpnService: VpnService?, type: Int): List<InetAddress> = emptyList()
    suspend fun queryHttpsRecord(host: String, vpnService: VpnService?): List<DnsPacketEngine.DnsRecord> = emptyList()
    suspend fun queryDohJson(host: String, vpnService: VpnService?, type: Int): List<InetAddress> = emptyList()
    suspend fun queryDohRacing(host: String, vpnService: VpnService?, type: Int): List<InetAddress> = emptyList()
    suspend fun queryDohExtreme(host: String, vpnService: VpnService?, type: Int): List<InetAddress> = emptyList()
    suspend fun queryDohSmuggling(host: String, vpnService: VpnService?, type: Int): List<InetAddress> = emptyList()
}

object DotDnsProtocols {
    fun clearPool() {}
    suspend fun queryDot(host: String, dotIp: String, vpnService: VpnService?, type: Int): List<InetAddress> = emptyList()
}
