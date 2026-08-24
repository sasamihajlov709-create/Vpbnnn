import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/CensorshipExpert.kt", "r") as f:
    content = f.read()

content = content.replace("BypassConfig.setMtu(targetMtu)", "// BypassConfig.setMtu(targetMtu) // Handled by DpiPolicyEngine")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/CensorshipExpert.kt", "w") as f:
    f.write(content)

