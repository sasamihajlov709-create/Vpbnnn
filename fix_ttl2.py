with open('app/src/main/java/com/aistudio/pinkproxy/fresh/AutoTtlProber.kt', 'r') as f:
    text = f.read()

old = """    private suspend fun estimateDistance(addr: InetAddress, port: Int, vpnService: VpnService?): Int {
        return kotlinx.coroutines.withContext(ProxyDispatcher.io) {
            val ttls = listOf(4, 8, 12, 16, 20, 24, 28, 32)
            val deferreds = ttls.associateWith { ttl -> 
                kotlinx.coroutines.async { tryConnect(addr, port, ttl, vpnService) }
            }"""

new = """    private suspend fun estimateDistance(addr: InetAddress, port: Int, vpnService: VpnService?): Int {
        return kotlinx.coroutines.withContext(ProxyDispatcher.io) {
            kotlinx.coroutines.coroutineScope {
                val ttls = listOf(4, 8, 12, 16, 20, 24, 28, 32)
                val deferreds = ttls.associateWith { ttl -> 
                    kotlinx.coroutines.async { tryConnect(addr, port, ttl, vpnService) }
                }"""

old2 = """            if (upperBound != -1) {
                val fineTtls = ((upperBound - 3) until upperBound).toList()
                val fineDeferreds = fineTtls.associateWith { ttl -> 
                    kotlinx.coroutines.async { tryConnect(addr, port, ttl, vpnService) }
                }
                for (ttl in fineTtls) {
                    if (fineDeferreds[ttl]?.await() == true) return@withContext ttl
                }
                return@withContext upperBound
            }
            return@withContext -1
        }
    }"""

new2 = """            if (upperBound != -1) {
                val fineTtls = ((upperBound - 3) until upperBound).toList()
                val fineDeferreds = fineTtls.associateWith { ttl -> 
                    kotlinx.coroutines.async { tryConnect(addr, port, ttl, vpnService) }
                }
                for (ttl in fineTtls) {
                    if (fineDeferreds[ttl]?.await() == true) return@coroutineScope ttl
                }
                return@coroutineScope upperBound
            }
            return@coroutineScope -1
            }
        }
    }"""

text = text.replace(old, new)
text = text.replace(old2, new2)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/AutoTtlProber.kt', 'w') as f:
    f.write(text)
print("done")
