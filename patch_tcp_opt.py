import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

find = """            // Optimization: Set buffer sizes based on strategy to influence TCP window
            if (strategy == BypassStrategy.WINDOW_SIZE || strategy == BypassStrategy.TCP_ZERO_WINDOW) {
                target.receiveBufferSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(512, 1024 + 1)
                target.sendBufferSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(512, 1024 + 1)
            } else if (strategy == BypassStrategy.TCP_WINDOW_CLAMP) {
                target.receiveBufferSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(128, 256 + 1)
                target.sendBufferSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(128, 256 + 1)
            }"""

repl = """            // Optimization: Set buffer sizes based on strategy to influence TCP window
            if (strategy == BypassStrategy.WINDOW_SIZE || strategy == BypassStrategy.TCP_ZERO_WINDOW) {
                target.receiveBufferSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(512, 1024 + 1)
                target.sendBufferSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(512, 1024 + 1)
            } else if (strategy == BypassStrategy.TCP_WINDOW_CLAMP) {
                target.receiveBufferSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(128, 256 + 1)
                target.sendBufferSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(128, 256 + 1)
            } else {
                target.receiveBufferSize = 2 * 1024 * 1024 // 2MB for QUIC/Streaming
                target.sendBufferSize = 2 * 1024 * 1024
            }
            try {
                // Enable TCP_NODELAY (disable Nagle's algorithm) for lower latency
                target.tcpNoDelay = true
                client.tcpNoDelay = true
                
                // TCP KeepAlive to maintain NAT tables
                if (strategy == BypassStrategy.TCP_KEEPALIVE) {
                    target.keepAlive = true
                    client.keepAlive = true
                }
            } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }"""

if find in content:
    content = content.replace(find, repl)
else:
    print("Could not find block 1")

find2 = """            // Optimize timeouts for the active streaming phase
            client.soTimeout = 90000
            target.soTimeout = 90000"""

repl2 = """            // Optimize timeouts for the active streaming phase
            client.soTimeout = 120000
            target.soTimeout = 120000"""

if find2 in content:
    content = content.replace(find2, repl2)
else:
    print("Could not find block 2")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)

