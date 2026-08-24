import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiPolicyEngine.kt", "r") as f:
    content = f.read()

content = content.replace("val currentMtu = BypassConfig.currentMtu.value", "val currentMtu = BypassConfig.getMtuForTransport(transport)")
content = content.replace("BypassConfig.currentMtu.value < 1400", "currentMtu < 1400")
content = content.replace("recommendedMtu = BypassConfig.currentMtu.value + 16", "recommendedMtu = currentMtu + 16")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiPolicyEngine.kt", "w") as f:
    f.write(content)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/CensorshipExpert.kt", "r") as f:
    content = f.read()

# Censorship expert MTU tuning should be TCP focused for now as a fallback
content = content.replace("val currentMtu = BypassConfig.currentMtu.value", "val currentMtu = BypassConfig.getMtuForTransport(TransportType.TCP)")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/CensorshipExpert.kt", "w") as f:
    f.write(content)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt", "r") as f:
    content = f.read()

content = content.replace("ProxyStats.updateCensorshipIntensity", "/* ProxyStats.updateCensorshipIntensity")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt", "w") as f:
    f.write(content)

