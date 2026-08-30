import os

path = '/app/applet/app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyExecutor.kt'
with open(path, 'r') as f:
    content = f.read()

content = content.replace(
    'val random: ThreadLocalRandom = ThreadLocalRandom.current()\n)',
    'val random: ThreadLocalRandom = ThreadLocalRandom.current(),\n    val isFirstPacket: Boolean = true\n)'
)

with open(path, 'w') as f:
    f.write(content)
