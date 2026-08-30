import os

path = '/app/applet/app/src/main/java/com/aistudio/pinkproxy/fresh/BypassApplier.kt'
with open(path, 'r') as f:
    content = f.read()

content = content.replace(
    'suspend fun applyBypass(socket: Socket, output: OutputStream, data: ByteArray, length: Int, config: SessionConfig, host: String) {',
    'suspend fun applyBypass(socket: Socket, output: OutputStream, data: ByteArray, length: Int, config: SessionConfig, host: String, isFirstPacket: Boolean = true) {'
)

content = content.replace(
    'val tcpContext = TcpExecutionContext(\n            socket = socket,\n            output = output,\n            data = finalData,\n            length = finalLen,\n            host = host,\n            strategy = strategy,\n            config = config,\n            effectiveDelayMs = effectiveDelay,\n            random = rnd\n        )',
    'val tcpContext = TcpExecutionContext(\n            socket = socket,\n            output = output,\n            data = finalData,\n            length = finalLen,\n            host = host,\n            strategy = strategy,\n            config = config,\n            effectiveDelayMs = effectiveDelay,\n            random = rnd,\n            isFirstPacket = isFirstPacket\n        )'
)

with open(path, 'w') as f:
    f.write(content)
