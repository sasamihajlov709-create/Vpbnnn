import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

find = """        if (ProxyStats.censorshipIntensity.value > 85) {
            val chaosPool = listOf(
                BypassStrategy.TCP_OOB_DESYNC, 
                BypassStrategy.FAKE_PACKET, 
                BypassStrategy.FRAGMENT_MULTI,
                BypassStrategy.SNI_SPLIT,
                BypassStrategy.PACKET_PADDING,
                BypassStrategy.CHAOS
            )
            return chaosPool.random()
        }"""

repl = """        if (ProxyStats.censorshipIntensity.value > 85) {
            val chaosPool = listOf(
                BypassStrategy.TCP_OOB_DESYNC, 
                BypassStrategy.FAKE_PACKET, 
                BypassStrategy.FRAGMENT_MULTI,
                BypassStrategy.SNI_SPLIT,
                BypassStrategy.PACKET_PADDING,
                BypassStrategy.CHAOS
            )
            return chaosPool.random()
        }
        
        if (lHost.contains("youtube") || lHost.contains("googlevideo")) {
             return BypassStrategy.QUIC_BOOST
        }
        if (lHost.contains("discord") || lHost.contains("telegram")) {
             return BypassStrategy.TCP_OOB_DESYNC
        }"""

if find in content:
    content = content.replace(find, repl)
else:
    print("Could not find block")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
