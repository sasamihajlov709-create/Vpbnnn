import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt", "r") as f:
    text = f.read()

replacement = """                    includeIpv6 = false,
                    isExcludeMode = isExcludeMode,
                    selectedPackages = selectedPackages,"""

text = re.sub(r'                    includeIpv6 = false,\s+isExcludeMode = true,\s+selectedPackages = emptySet\(\),', replacement, text)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt", "w") as f:
    f.write(text)
