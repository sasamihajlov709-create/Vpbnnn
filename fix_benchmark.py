import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

old_code = """        if (minRtt != Long.MAX_VALUE) {
            ProxyStats.logRecovery("BENCHMARK: Best strategy found: $bestStrategy ($minRtt ms). Promoting to global.")
            setGlobalStrategy(bestStrategy)
            ProxyStats.logRecovery("BENCHMARK: All candidates failed. Remaining on current strategy.")
        }"""
        
new_code = """        if (minRtt != Long.MAX_VALUE) {
            ProxyStats.logRecovery("BENCHMARK: Best strategy found: $bestStrategy ($minRtt ms). Promoting to global.")
            setGlobalStrategy(bestStrategy)
        } else {
            ProxyStats.logRecovery("BENCHMARK: All candidates failed. Remaining on current strategy.")
        }"""

if old_code in content:
    content = content.replace(old_code, new_code)
    with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
        f.write(content)
