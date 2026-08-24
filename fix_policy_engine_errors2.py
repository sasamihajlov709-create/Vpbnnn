import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiPolicyEngine.kt", "r") as f:
    content = f.read()

content = content.replace("BypassConfig.getMtuForTransport(transport) < 1400", "BypassConfig.getMtuForTransport(transport) < 1400")
# Make sure we don't have dangling currentMtu
content = re.sub(r"recommendedMtu = currentMtu \+ 16", "recommendedMtu = BypassConfig.getMtuForTransport(transport) + 16", content)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiPolicyEngine.kt", "w") as f:
    f.write(content)

