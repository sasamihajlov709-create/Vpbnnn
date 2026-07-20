with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

import re

new_handleClient = """
    private suspend fun handleClient(client: Socket) {
        if (!activeConnectionSemaphore.tryAcquire()) {
            try { client.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
            return
        }
        ProxyStats.addConnection()
        try {
            client.soTimeout = 10000; client.tcpNoDelay = true
            val input = client.getInputStream(); val output = client.getOutputStream()
            val headerBuffer = BypassConfig.TrafficShaper.acquireBuffer(8192)
            try {
                val read = input.read(headerBuffer)
                if (read <= 0) { client.close(); return }
                
                if (headerBuffer[0] == 0x05.toByte()) {
                    handleSocks5(client, headerBuffer, read, output, input)
                    return
                }
                
                val header = String(headerBuffer, 0, read, Charsets.UTF_8)
                val firstLine = header.substringBefore("\\r").substringBefore("\\n").trim()
                if (firstLine.startsWith("CONNECT", ignoreCase = true)) {
                    val parts = firstLine.split(" ")
                    if (parts.size >= 2) {
                        val hostPort = parts[1]
                        val host = hostPort.substringBefore(":")
                        val portStr = hostPort.substringAfter(":", "443")
                        val port = portStr.toIntOrNull() ?: 443
                        handleHttps(client, host, port, output, input)
                    } else {
                        client.close()
                    }
                } else { handleHttp(client, header, output, input) }
            } finally {
                BypassConfig.TrafficShaper.releaseBuffer(headerBuffer)
            }
        } catch (e: Exception) { 
            ProxyStats.addError() 
        } finally { 
            try { client.close() } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
            ProxyStats.removeConnection() 
            activeConnectionSemaphore.release()
        }
    }
"""

content = re.sub(r'private suspend fun handleClient\(client: Socket\) \{.*?(?=private suspend fun handleHttps)', new_handleClient.strip() + '\n\n    ', content, flags=re.DOTALL)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
