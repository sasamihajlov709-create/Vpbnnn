with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    text = f.read()

import re

old_text = """                    if (!activeConnectionSemaphore.tryAcquire()) {
                        try { client.close() } catch (e: Throwable) {}
                        continue
                    }
                    
                    val clientJob = scope.launch {
                        try {
                            client.tcpNoDelay = true
                            try { client.sendBufferSize = 64 * 1024 } catch (e: Throwable) {}
                            try { client.receiveBufferSize = 64 * 1024 } catch (e: Throwable) {}
                            handleClient(client, this)
                        } finally {
                            activeConnectionSemaphore.release()
                        }
                    }"""

new_text = """                    if (!activeConnectionSemaphore.tryAcquire()) {
                        try { client.close() } catch (e: Throwable) {}
                        continue
                    }
                    ProxyStats.updateConnections(1)
                    
                    val clientJob = scope.launch {
                        try {
                            client.tcpNoDelay = true
                            try { client.sendBufferSize = 64 * 1024 } catch (e: Throwable) {}
                            try { client.receiveBufferSize = 64 * 1024 } catch (e: Throwable) {}
                            handleClient(client, this)
                        } finally {
                            ProxyStats.updateConnections(-1)
                            activeConnectionSemaphore.release()
                        }
                    }"""

if old_text in text:
    text = text.replace(old_text, new_text)
    with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
        f.write(text)
    print("Fixed connections leak")
else:
    print("Not found")
