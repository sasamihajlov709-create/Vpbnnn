with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportManager.kt", "r") as f:
    text = f.read()

import re

old_sni = r'''    suspend fun performSniGhosting\(decoy: String, vpnService: VpnService\?\) \{
        try \{
            val s = Socket\(\)
            vpnService\?\.protect\(s\)
            val resolved = RobustResolver\.resolveDual\(decoy, vpnService\)
            if \(resolved\.isNotEmpty\(\)\) \{
                s\.connect\(InetSocketAddress\(resolved\.random\(\), 443\), 2000\)
                val out = s\.getOutputStream\(\)
                val hello = FakePacketHelper\.buildRealisticTlsHello\(decoy\)
                
                val discoveredTtl = BypassConfig\.fakeTtl\.takeIf \{ it > 0 \} \?: AutoTtlProber\.getDiscoveredTtl\(decoy\) \?: 4
                TtlHelper\.setTtl\(s, discoveredTtl\)
                
                out\.write\(hello\)
                out\.flush\(\)
                kotlinx\.coroutines\.delay\(10\)
                s\.close\(\)
            \}
        \} catch \(e: CancellationException\) \{'''
new_sni = '''    suspend fun performSniGhosting(decoy: String, vpnService: VpnService?) {
        var s: Socket? = null
        try {
            s = Socket()
            vpnService?.protect(s)
            val resolved = RobustResolver.resolveDual(decoy, vpnService)
            if (resolved.isNotEmpty()) {
                s.connect(InetSocketAddress(resolved.random(), 443), 2000)
                val out = s.getOutputStream()
                val hello = FakePacketHelper.buildRealisticTlsHello(decoy)
                
                val discoveredTtl = BypassConfig.fakeTtl.takeIf { it > 0 } ?: AutoTtlProber.getDiscoveredTtl(decoy) ?: 4
                TtlHelper.setTtl(s, discoveredTtl)
                
                out.write(hello)
                out.flush()
                kotlinx.coroutines.delay(10)
            }
        } catch (e: CancellationException) {'''

text = re.sub(old_sni, new_sni, text)

old_sni_end = r'''        \} catch \(e: Throwable\) \{
            Log\.e\("TcpTransportManager", "Critical SNI ghosting error", e\)
        \}
    \}'''
new_sni_end = '''        } catch (e: Throwable) {
            Log.e("TcpTransportManager", "Critical SNI ghosting error", e)
        } finally {
            try { s?.close() } catch (ignored: Exception) {}
        }
    }'''

text = re.sub(old_sni_end, new_sni_end, text)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportManager.kt", "w") as f:
    f.write(text)
