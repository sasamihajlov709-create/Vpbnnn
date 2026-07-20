import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

find = """                                if (!target.isClosed && target.isConnected) {
                    val lHost = host.lowercase(java.util.Locale.ROOT)
                    val pool = connectionPool.getOrPut(lHost + ":" + port) { java.util.concurrent.LinkedBlockingQueue(MAX_POOL_SIZE) }
                    if (pool.size < MAX_POOL_SIZE) {
                        pool.offer(PooledConnection(target))
                        target = null // Prevent closing in finally
                    } else {
                        target.close()
                    }
                }"""

repl = """                                // NEVER return a used socket to the pool for opaque tunnels.
                // The pre-warmer will create fresh sockets instead.
                try { target.close() } catch (e: Exception) {}"""

if find in content:
    content = content.replace(find, repl)
    print("Patched connection pool reuse.")
else:
    print("Failed to find connection pool reuse block.")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
