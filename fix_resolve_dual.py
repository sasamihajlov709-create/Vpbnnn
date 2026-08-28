import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RobustResolver.kt", "r") as f:
    text = f.read()

replacement = """    suspend fun resolveDual(host: String, vpnService: VpnService? = null): List<InetAddress> = kotlinx.coroutines.coroutineScope {
        if (!BypassConfig.includeIpv6) return@coroutineScope resolve(host, vpnService, 1)

        val aDeferred = kotlinx.coroutines.async { try { resolve(host, vpnService, 1) } catch (e: Exception) { if (e is kotlinx.coroutines.CancellationException) throw e; emptyList() } }
        val aaaaDeferred = kotlinx.coroutines.async { try { resolve(host, vpnService, 28) } catch (e: Exception) { if (e is kotlinx.coroutines.CancellationException) throw e; emptyList() } }

        val aResult = aDeferred.await()
        val aaaaResult = aaaaDeferred.await()

        // Prefer AAAA if available, but return all for selection
        (aaaaResult + aResult).distinct()
    }"""

text = re.sub(r'    suspend fun resolveDual\(host: String, vpnService: VpnService\? = null\): List<InetAddress> \{.*?    \}', replacement, text, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RobustResolver.kt", "w") as f:
    f.write(text)
