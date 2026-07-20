import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

find = """    fun runGlobalOptimization() {"""

repl = """    private fun startPreWarmer() {
        serverScope.launch {
            while (isActive) {
                delay(20000)
                try {
                    // Pre-warm connections for the top 3 hosts to achieve 0-RTT connection latency
                    val top = _topHosts.value.take(3).map { it.first }
                    for (host in top) {
                        val lHost = host.lowercase(java.util.Locale.ROOT)
                        val port = 443
                        val pool = connectionPool.getOrPut(lHost + ":" + port) { java.util.concurrent.LinkedBlockingQueue(MAX_POOL_SIZE) }
                        
                        if (pool.size < 2) { // Keep at least 2 warm connections
                            val ips = RobustResolver.resolve(host, vpnService)
                            if (ips.isNotEmpty()) {
                                val sock = java.net.Socket()
                                vpnService?.protect(sock)
                                sock.soTimeout = 10000
                                kotlinx.coroutines.withTimeoutOrNull(5000) {
                                    sock.connect(java.net.InetSocketAddress(ips.first(), port), 3000)
                                    pool.offer(PooledConnection(sock))
                                }
                            }
                        }
                    }
                } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
            }
        }
    }

    fun runGlobalOptimization() {"""

if find in content:
    content = content.replace(find, repl)
else:
    print("Failed to find runGlobalOptimization")

find2 = """    init {
        serverScope.launch {"""

repl2 = """    init {
        startPreWarmer()
        serverScope.launch {"""

if find2 in content:
    content = content.replace(find2, repl2)
else:
    print("Failed to find init block")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
