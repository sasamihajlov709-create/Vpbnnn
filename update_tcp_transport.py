import os

path = '/app/applet/app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt'
with open(path, 'r') as f:
    content = f.read()

content = content.replace(
    'BypassApplier.applyBypass(finalRemoteSocket, finalRemoteOut, clientBuffer, read, config, targetHost)',
    'BypassApplier.applyBypass(finalRemoteSocket, finalRemoteOut, clientBuffer, read, config, targetHost, isFirstPacket = false)'
)

with open(path, 'w') as f:
    f.write(content)
