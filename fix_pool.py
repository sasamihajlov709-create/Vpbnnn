import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

find = """                    for (host in top) {
                        val port = 443
                        
                        if (pool.size < 2) { // Keep at least 2 warm connections"""

repl = """                    for (host in top) {
                        val port = 443
                        val lHost = host.lowercase(java.util.Locale.ROOT)
                        val pool = connectionPool.getOrPut(lHost + ":" + port) { java.util.concurrent.LinkedBlockingQueue(MAX_POOL_SIZE) }
                        
                        if (pool.size < 2) { // Keep at least 2 warm connections"""

if find in content:
    content = content.replace(find, repl)
else:
    print("Not found")
    
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
