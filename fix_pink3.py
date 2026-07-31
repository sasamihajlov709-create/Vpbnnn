with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    text = f.read()

import re

text = re.sub(r'activeConnectionSemaphore\.tryAcquire\(\)\) \{\n(.*?)continue\n(.*?)\}\n(.*?)\n(.*?)val clientJob = scope\.launch \{', 
              r'activeConnectionSemaphore.tryAcquire()) {\n\1continue\n\2}\n\3\n                    ProxyStats.updateConnections(1)\n\4val clientJob = scope.launch {', text, flags=re.DOTALL)

text = re.sub(r'handleClient\(client, this\)\n(.*?)} finally \{\n(.*?)activeConnectionSemaphore.release\(\)',
              r'handleClient(client, this)\n\1} finally {\n\2ProxyStats.updateConnections(-1)\n\2activeConnectionSemaphore.release()', text, flags=re.DOTALL)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(text)
print("done")
