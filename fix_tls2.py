with open('app/src/main/java/com/aistudio/pinkproxy/fresh/TlsStrategyHandler.kt', 'r') as f:
    content = f.read()

content = content.replace('if (context.isFirstPacket)', 'if (isFirstPacket)')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/TlsStrategyHandler.kt', 'w') as f:
    f.write(content)
