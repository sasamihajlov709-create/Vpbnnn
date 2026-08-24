import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiPolicyEngine.kt", "r") as f:
    content = f.read()

content = content.replace("currentMtu < 1400", "BypassConfig.getMtuForTransport(transport) < 1400")
content = content.replace("recommendedMtu = currentMtu + 16", "recommendedMtu = BypassConfig.getMtuForTransport(transport) + 16")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiPolicyEngine.kt", "w") as f:
    f.write(content)

