import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

find = """                    if (rtt < 150) {
                        val cwnd = congestionWindow.incrementAndGet().coerceAtMost(50)
                        ProxyStats.updateCongestionWindow(cwnd)
                        val cwnd = congestionWindow.decrementAndGet().coerceAtLeast(5)
                        ProxyStats.updateCongestionWindow(cwnd)
                    }"""

repl = """                    if (rtt < 150) {
                        val cwnd = congestionWindow.incrementAndGet().coerceAtMost(50)
                        ProxyStats.updateCongestionWindow(cwnd)
                    } else {
                        val cwnd = congestionWindow.decrementAndGet().coerceAtLeast(5)
                        ProxyStats.updateCongestionWindow(cwnd)
                    }"""

if find in content:
    content = content.replace(find, repl)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
