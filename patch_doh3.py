import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DnsProtocolImpls.kt', 'r') as f:
    content = f.read()

new_doh = """    suspend fun queryDohOverQuic(host: String, dnsIp: String, vpnService: VpnService?, type: Int): List<InetAddress> {
        try {
            val engine = com.aistudio.pinkproxy.fresh.cronet.CronetEngineProvider.getEngine()
            if (engine != null) {
                val transport = com.aistudio.pinkproxy.fresh.cronet.CronetDohTransport(engine)
                val queryId = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)
                val query = DnsPacketEngine.buildDnsQuery(host, type, id = queryId)
                
                // Construct DoH URL from dnsIp or use default
                val url = if (dnsIp.startsWith("http")) dnsIp else "https://$dnsIp/dns-query"
                
                val responseBytes = transport.resolveDoH(url, query)
                if (responseBytes != null && responseBytes.isNotEmpty()) {
                    return DnsPacketEngine.parseDnsResponse(responseBytes, responseBytes.size, expectedId = queryId, expectedHost = host)
                }
            }
            // Fallback if Cronet is not available or fails
            val dotRes = DotDnsProtocols.queryDot(host, dnsIp, vpnService, type)
            if (dotRes.isNotEmpty()) return dotRes
            return DohDnsProtocols.queryDohRacing(host, vpnService, type)
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            return emptyList()
        }
    }"""

# Replace the existing queryDohOverQuic
content = re.sub(
    r'    suspend fun queryDohOverQuic.*?return emptyList\(\)\n        \}\n    \}',
    new_doh,
    content,
    flags=re.DOTALL
)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DnsProtocolImpls.kt', 'w') as f:
    f.write(content)

