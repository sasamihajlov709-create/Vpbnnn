with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'r') as f:
    text = f.read()

import re

old_dns = """                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")"""

new_dns = """                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .addDnsServer("2606:4700:4700::1111")
                .addDnsServer("2001:4860:4860::8888")"""

if old_dns in text:
    text = text.replace(old_dns, new_dns)
    with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'w') as f:
        f.write(text)
    print("Fixed IPv6 DNS")
else:
    print("Not found")

