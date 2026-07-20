with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

import re

# Fix 1: check for instance
content = content.replace(
    'if (channel is java.nio.channels.SocketChannel) {',
    'if (true) {'
)

# Fix 2: toByte deprecations
content = content.replace(
    "mData[i + hBytes.size] = '.'.toByte()",
    "mData[i + hBytes.size] = '.'.code.toByte()"
)
content = content.replace(
    "if (c.isLowerCase()) c.uppercaseChar().toByte() else c.lowercaseChar().toByte()",
    "if (c.isLowerCase()) c.uppercaseChar().code.toByte() else c.lowercaseChar().code.toByte()"
)

# Fix 3: target != null
content = content.replace(
    'if (target != null && !target.isClosed && target.isConnected) {',
    'if (!target.isClosed && target.isConnected) {'
)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
