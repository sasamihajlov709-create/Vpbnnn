import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiPolicyEngine.kt", "r") as f:
    content = f.read()

content = content.replace("BypassConfig.setMtu(newMtu)", "// BypassConfig.setMtu(newMtu)")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiPolicyEngine.kt", "w") as f:
    f.write(content)

