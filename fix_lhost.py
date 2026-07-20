import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

content = content.replace("fun getDnaForHost(host: String): String {", "fun getDnaForHost(host: String): String {\n        val lHost = host.lowercase(java.util.Locale.ROOT)")

content = content.replace("val poolQueue = connectionPool[lHost + \":\" + port]", "val lHost = host.lowercase(java.util.Locale.ROOT)\n        val poolQueue = connectionPool[lHost + \":\" + port]")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
