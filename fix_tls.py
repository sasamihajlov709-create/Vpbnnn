with open('app/src/main/java/com/aistudio/pinkproxy/fresh/TlsStrategyHandler.kt', 'r') as f:
    content = f.read()

content = content.replace(
    'suspend fun handleTlsStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy) {',
    'suspend fun handleTlsStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy, isFirstPacket: Boolean = true) {'
)

content = content.replace(
'''        handleTlsStrategies(
            socket = context.socket,
            output = context.output,
            data = context.data,
            length = context.length,
            rnd = context.random,
            host = context.host,
            strategy = context.strategy
        )''',
'''        handleTlsStrategies(
            socket = context.socket,
            output = context.output,
            data = context.data,
            length = context.length,
            rnd = context.random,
            host = context.host,
            strategy = context.strategy,
            isFirstPacket = context.isFirstPacket
        )'''
)

content = content.replace('!context.isFirstPacket', '!isFirstPacket')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/TlsStrategyHandler.kt', 'w') as f:
    f.write(content)
