import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    content = f.read()

content = content.replace("var effectiveStrategy = if (isPanicMode && rnd.nextInt(100) < 80) BypassStrategy.BYEBYEDPI_HYBRID else strategy", "var effectiveStrategy = if (isPanicModeForTransport(transport) && rnd.nextInt(100) < 80) BypassStrategy.BYEBYEDPI_HYBRID else strategy")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "w") as f:
    f.write(content)

