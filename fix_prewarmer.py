import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

find = """    private fun startPreWarmer() {
        serverScope.launch {
            while (isActive) {
                delay(20000)
                try {
                    // Pre-warm connections for the top 3 hosts to achieve 0-RTT connection latency
                    val top = _topHosts.value.take(3).map { it.first }"""

repl = """    private fun startPreWarmer() {
        serverScope.launch {
            while (isActive) {
                delay(20000)
                try {
                    // Pre-warm connections for the top 3 hosts to achieve 0-RTT connection latency
                    val top = ProxyStats.topHosts.value.take(3).map { it.first }"""

if find in content:
    content = content.replace(find, repl)
else:
    print("Could not find startPreWarmer block")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
