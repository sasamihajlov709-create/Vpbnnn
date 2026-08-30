import os

path = '/app/applet/app/src/main/java/com/aistudio/pinkproxy/fresh/AdaptiveStrategyHandler.kt'
with open(path, 'r') as f:
    content = f.read()

# Fix handleAdaptiveStrategies signature
content = content.replace(
    'suspend fun handleAdaptiveStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy, config: SessionConfig) {',
    'suspend fun handleAdaptiveStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy, config: SessionConfig, isFirstPacket: Boolean) {'
)

# Fix executeTcp call to handleAdaptiveStrategies
content = content.replace(
    'handleAdaptiveStrategies(socket, output, data, length, rnd, host, context.strategy, config)',
    'handleAdaptiveStrategies(socket, output, data, length, rnd, host, context.strategy, config, context.isFirstPacket)'
)

# Fix 'context.isFirstPacket' to 'isFirstPacket'
content = content.replace('context.isFirstPacket', 'isFirstPacket')

with open(path, 'w') as f:
    f.write(content)
