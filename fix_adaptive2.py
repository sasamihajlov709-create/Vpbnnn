import os

path = '/app/applet/app/src/main/java/com/aistudio/pinkproxy/fresh/AdaptiveStrategyHandler.kt'
with open(path, 'r') as f:
    content = f.read()

content = content.replace(
    'strategy = context.strategy,\n            config = context.config\n        )',
    'strategy = context.strategy,\n            config = context.config,\n            isFirstPacket = context.isFirstPacket\n        )'
)

with open(path, 'w') as f:
    f.write(content)
