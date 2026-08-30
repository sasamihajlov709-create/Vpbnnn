import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'r') as f:
    content = f.read()

content = content.replace("isStopping = false", "isStopping = false\n        startDynamicNotification()")
content = content.replace("isStopping = true", "isStopping = true\n        stopDynamicNotification()")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'w') as f:
    f.write(content)
