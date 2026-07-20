import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

content = content.replace(
'''        } finally { 
            client.close()
            ProxyStats.removeConnection() 
            activeConnectionSemaphore.release()
        }''',
'''        } finally { 
            try { client.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
            ProxyStats.removeConnection() 
            activeConnectionSemaphore.release()
        }''')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
