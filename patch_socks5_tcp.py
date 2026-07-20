import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

find = """            // Check if we need to send initial fake client hello or if it's raw
            // SOCKS5 doesn't have an initial client hello in the buffer, it's a pure transparent TCP stream from now on.
            // But we can apply traffic shaping!
            
            client.soTimeout = 90000
            target.soTimeout = 90000
            
            coroutineScope {
                val c2t = launch { proxyStream(clientIn, targetOut, { try { target?.close() } catch (e: Exception) {} }, host, false, strategy) }"""

repl = """            // We must apply bypass on the first chunk of data!
            val helloBuffer = BypassConfig.TrafficShaper.acquireBuffer(8192)
            try {
                val helloRead = clientIn.read(helloBuffer)
                if (helloRead > 0) {
                    try {
                        val config = BypassConfig.getSessionConfig(host, strategy, 100L)
                        BypassConfig.applyBypass(target, targetOut, helloBuffer, helloRead, config, host)
                        BypassConfig.reportSuccess(host, strategy)
                        BypassConfig.recordStrategyResult(host, strategy, true)
                    } catch (e: java.io.IOException) {
                        if (e.message?.contains("reset", ignoreCase = true) == true) {
                            BypassConfig.recordDpiFault(host)
                        }
                        throw e
                    }
                }
            } finally {
                BypassConfig.TrafficShaper.releaseBuffer(helloBuffer)
            }
            
            client.soTimeout = 90000
            target.soTimeout = 90000
            
            coroutineScope {
                val c2t = launch { proxyStream(clientIn, targetOut, { try { target?.close() } catch (e: Exception) {} }, host, false, strategy) }"""

if find in content:
    content = content.replace(find, repl)
else:
    print("Failed to find block.")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)

