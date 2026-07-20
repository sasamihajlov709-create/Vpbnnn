with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

import re

new_code = """
        var target: Socket? = null
        val poolQueue = connectionPool[lHost + ":" + port]
        if (poolQueue != null) {
            var pc = poolQueue.poll()
            while (pc != null) {
                if (pc.isAlive()) {
                    target = pc.socket
                    break
                } else {
                    try { pc.socket.close() } catch (e: Exception) {}
                }
                pc = poolQueue.poll()
            }
        }
"""

content = re.sub(
    r'var target: Socket\? = connectionPool\[lHost \+ ":" \+ port\]\?\.poll\(\)\?\.socket\s*if \(target != null && \(target\.isClosed \|\| !target\.isConnected\)\) \{\s*try \{ target\.close\(\) \} catch \(e: Exception\) \{\}\s*target = null\s*\}',
    new_code.strip(),
    content
)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
