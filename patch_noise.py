import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

find = """        coroutineScope {
            // Background Keep-Alive Noise
            val noiseJob = if (!isRecv && strategy != null && strategy != BypassStrategy.DIRECT) {
                launch {
                    try {
                        val rnd = java.util.concurrent.ThreadLocalRandom.current()
                        while (isActive) {
                            delay(rnd.nextLong(30000, 60001))
                            if (System.currentTimeMillis() - lastActivity > 25000) {
                                val noise = ByteArray(rnd.nextInt(1, 5))
                                rnd.nextBytes(noise)
                                synchronized(output) {
                                    output.write(noise)
                                    output.flush()
                                }
                                ProxyStats.logRecovery("CORE: Keep-alive for ${host ?: "unknown"}")
                            }
                        }
                    } catch (e: Exception) {}
                }
            } else null
            
            try {"""

repl = """        coroutineScope {
            try {"""

if find in content:
    content = content.replace(find, repl)
else:
    print("Failed to find block.")

find2 = """                // Cancel noise injection when stream closes
                noiseJob?.cancel()"""
repl2 = """"""
if find2 in content:
    content = content.replace(find2, repl2)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
