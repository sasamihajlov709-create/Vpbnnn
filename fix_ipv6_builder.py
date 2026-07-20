import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'r') as f:
    content = f.read()

content = content.replace(
'''            val builder = Builder()
                .addAddress("10.0.0.2", 24)
                .addAddress("fd00:1:2:3::2", 120)
                .addRoute("::", 0) // Blackhole all IPv6 to prevent leaks bypassing the proxy
                .addDnsServer("10.0.0.3")''',
'''            val builder = Builder()
                .addAddress("10.0.0.2", 24)
                .addDnsServer("10.0.0.3")
            try {
                builder.addAddress("fd00:1:2:3::2", 120)
                builder.addRoute("::", 0) // Blackhole all IPv6 to prevent leaks bypassing the proxy
            } catch (e: Exception) {
                Log.w("PinkVpnService", "IPv6 not supported on this device, skipping IPv6 routes")
            }''')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'w') as f:
    f.write(content)
