with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    text = f.read()

import re

old = """                            handleClient(client, this)
                        } finally {
                    
                        ProxyStats.updateConnections(-1)
                    
                        activeConnectionSemaphore.release()
                        }"""

new = """                            handleClient(client, this)
                        } finally {
                            try { client.close() } catch (e: Throwable) {}
                            ProxyStats.updateConnections(-1)
                            activeConnectionSemaphore.release()
                        }"""

# Using regex for flexible whitespace
text = re.sub(r'handleClient\(client,\s*this\)\s*\}\s*finally\s*\{.*?ProxyStats\.updateConnections\(-1\).*?activeConnectionSemaphore\.release\(\)\s*\}', 
              r'handleClient(client, this)\n                        } finally {\n                            try { client.close() } catch (e: Throwable) {}\n                            ProxyStats.updateConnections(-1)\n                            activeConnectionSemaphore.release()\n                        }', text, flags=re.DOTALL)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(text)
print("done")
