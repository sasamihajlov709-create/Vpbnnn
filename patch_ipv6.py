import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/VpnTunnelManager.kt", "r") as f:
    text = f.read()

replacement = """                    if (tryIpv6) {
                        try {
                            // Assigning a ULA IPv6 address
                            builder.addAddress("fd00::2", 64)
                            builder.addRoute("::", 0)
                            // Note: We removed the hardcoded IPv6 DNS servers to respect user's DNS policy.
                            ipv6SetupSuccessful = true"""

text = re.sub(r'                    if \(tryIpv6\) \{\s+try \{\s+builder\.addAddress\("fd00::2", 64\)\s+builder\.addRoute\("::", 0\)\s+builder\.addDnsServer\("2606:4700:4700::1111"\)\s+builder\.addDnsServer\("2001:4860:4860::8888"\)\s+ipv6SetupSuccessful = true', replacement, text)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/VpnTunnelManager.kt", "w") as f:
    f.write(text)
