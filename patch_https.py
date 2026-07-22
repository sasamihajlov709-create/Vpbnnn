import sys
import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt", "r") as f:
    code = f.read()

code = re.sub(r'clientOut\.write\("HTTP/1\.1 200 Connection Established"\.toByteArray\(\)\)', r'clientOut.write("HTTP/1.1 200 Connection Established\\r\\n\\r\\n".toByteArray())', code)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt", "w") as f:
    f.write(code)
