import os

path = '/app/applet/app/src/main/java/com/aistudio/pinkproxy/fresh/TcpBasicStrategyHandler.kt'
with open(path, 'r') as f:
    content = f.read()

# Fix handleTcpStrategies signature
content = content.replace(
    'suspend fun handleTcpStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy) {',
    'suspend fun handleTcpStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy, isFirstPacket: Boolean) {'
)

# Fix executeTcp call
content = content.replace(
    'host = context.host,\n            strategy = context.strategy\n        )',
    'host = context.host,\n            strategy = context.strategy,\n            isFirstPacket = context.isFirstPacket\n        )'
)

with open(path, 'w') as f:
    f.write(content)
