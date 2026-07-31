with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DnsOptimizer.kt', 'r') as f:
    text = f.read()

import re
text = text.replace("val interval = if (ProxyStats.dnsFailureCount.value > 10) 10 * 60 * 1000L else 30 * 60 * 1000L",
"val interval = if (ProxyStats.dnsFailureCount.value > 10) 2 * 60 * 1000L else 15 * 60 * 1000L")
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DnsOptimizer.kt', 'w') as f:
    f.write(text)
