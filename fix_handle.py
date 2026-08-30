import os

path = '/app/applet/app/src/main/java/com/aistudio/pinkproxy/fresh/TcpBasicStrategyHandler.kt'
with open(path, 'r') as f:
    content = f.read()

content = content.replace(
    'strategy = context.strategy,\n            config = context.config\n        )',
    'strategy = context.strategy,\n            config = context.config,\n            isFirstPacket = context.isFirstPacket\n        )'
)

content = content.replace(
    'private suspend fun handleTcpStrategies(\n        socket: Socket,\n        output: OutputStream,\n        data: ByteArray,\n        length: Int,\n        rnd: ThreadLocalRandom,\n        host: String,\n        strategy: BypassStrategy,\n        config: SessionConfig\n    )',
    'private suspend fun handleTcpStrategies(\n        socket: Socket,\n        output: OutputStream,\n        data: ByteArray,\n        length: Int,\n        rnd: ThreadLocalRandom,\n        host: String,\n        strategy: BypassStrategy,\n        config: SessionConfig,\n        isFirstPacket: Boolean\n    )'
)

# Replace 'context.isFirstPacket' with 'isFirstPacket'
content = content.replace('!context.isFirstPacket', '!isFirstPacket')

with open(path, 'w') as f:
    f.write(content)
