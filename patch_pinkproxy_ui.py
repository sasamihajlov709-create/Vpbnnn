import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ui/PinkProxyApp.kt", "r") as f:
    content = f.read()

content = content.replace(
    "val censorshipIntensity by ProxyStats.censorshipIntensity.collectAsStateWithLifecycle(initialValue = 0)",
    """val censorshipIntensity by ProxyStats.censorshipIntensity.collectAsStateWithLifecycle(initialValue = 0)
    val tcpCensorshipIntensity by ProxyStats.tcpCensorshipIntensity.collectAsStateWithLifecycle(initialValue = 0)
    val udpCensorshipIntensity by ProxyStats.udpCensorshipIntensity.collectAsStateWithLifecycle(initialValue = 0)
    val dnsCensorshipIntensity by ProxyStats.dnsCensorshipIntensity.collectAsStateWithLifecycle(initialValue = 0)"""
)

content = content.replace(
    """                            isPanicMode = isPanicMode,
                            censorshipIntensity = censorshipIntensity""",
    """                            isPanicMode = isPanicMode,
                            tcpIntensity = tcpCensorshipIntensity,
                            udpIntensity = udpCensorshipIntensity,
                            dnsIntensity = dnsCensorshipIntensity"""
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ui/PinkProxyApp.kt", "w") as f:
    f.write(content)

