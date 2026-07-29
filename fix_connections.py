import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt", "r") as f:
    code = f.read()

# Make sure updateConnections(-1) is in a finally block at the end of handleClient
if "ProxyStats.updateConnections(-1)" not in code:
    code = code.replace(
        "ProxyStats.updateConnections(1)\n        try {",
        "ProxyStats.updateConnections(1)\n        try {"
    )
    # Actually let's just find the end of handleClient. 
    # Let's add a finally block to the try block that starts at `try {` after updateConnections(1)
    
    # Alternatively, just run `sed` or replace the last `} catch` with `} finally { ProxyStats.updateConnections(-1); try { client.close() } catch (e: Throwable) {} }`
    pass

