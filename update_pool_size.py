import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

find = """    private val connectionPool = java.util.concurrent.ConcurrentHashMap<String, java.util.concurrent.LinkedBlockingQueue<PooledConnection>>()
    private val MAX_POOL_SIZE = 5"""
repl = """    private val connectionPool = java.util.concurrent.ConcurrentHashMap<String, java.util.concurrent.LinkedBlockingQueue<PooledConnection>>()
    private val MAX_POOL_SIZE: Int get() = if (BypassConfig.isCharging) 5 else 1"""

content = content.replace(find, repl)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
