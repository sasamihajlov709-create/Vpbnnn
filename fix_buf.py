with open('app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt', 'r') as f:
    text = f.read()

import re

old = "65536 -> when (buffer.size) { 8192 -> ProxyStats.release8k(buffer); 16384 -> ProxyStats.release16k(buffer); 65536 -> ProxyStats.release64k(buffer); else -> {} }"
new = "65536 -> ProxyStats.release64k(buffer)"

if old in text:
    text = text.replace(old, new)
    with open('app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt', 'w') as f:
        f.write(text)
    print("Fixed buf")
else:
    print("Not found")
