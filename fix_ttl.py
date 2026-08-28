import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TtlHelper.kt", "r") as f:
    text = f.read()

text = re.sub(
r'    fun getSocketTtl\(socket: Socket\): Int \{\s+var ttl = BypassConfig\.currentTtl\s+withFd\(socket\) \{ fd ->\s+ttl = getsockoptInt\(fd, 0, 2\) // IPPROTO_IP=0, IP_TTL=2\s+\}\s+return ttl\s+\}\s+return ttl\s+\}',
"""    fun getSocketTtl(socket: Socket): Int {
        var ttl = BypassConfig.currentTtl
        withFd(socket) { fd ->
            ttl = getsockoptInt(fd, 0, 2) // IPPROTO_IP=0, IP_TTL=2
        }
        return ttl
    }""", text, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TtlHelper.kt", "w") as f:
    f.write(text)
