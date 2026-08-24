import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiStrategySelector.kt", "r") as f:
    content = f.read()

content = content.replace("if (DpiEngine.isPanicMode.value || ProxyStats.censorshipIntensity.value > 92)", "if (BypassConfig.isPanicModeForTransport(transport) || ProxyStats.censorshipIntensity.value > 92)")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiStrategySelector.kt", "w") as f:
    f.write(content)
