import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

find = """                    if (isRecv) BypassConfig.TrafficShaper.pace(BypassConfig.isPanicMode, r)"""
repl = """                    if (isRecv && r > 2048) BypassConfig.TrafficShaper.pace(BypassConfig.isPanicMode, r)"""

if find in content:
    content = content.replace(find, repl)
else:
    print("Could not find pace block")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
