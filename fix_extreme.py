with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DnsProtocols.kt', 'r') as f:
    text = f.read()

import re

old_extreme = """        return supervisorScope {
            val channel = kotlinx.coroutines.channels.Channel<List<InetAddress>>(hardcodedIps.size)
            val completed = java.util.concurrent.atomic.AtomicInteger(0)
            hardcodedIps.forEach { url ->
                launch(ProxyDispatcher.io) {
                    try {
                        val res = queryDoh(host, url, vpnService)
                        if (res.isNotEmpty()) channel.trySend(res)
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Throwable) {
                    } finally {
                        if (completed.incrementAndGet() == hardcodedIps.size) {
                            channel.close()
                        }
                    }
                }
            }
            try {
                withTimeoutOrNull(5000) { channel.receive() } ?: emptyList()
            } catch (e: Throwable) {
                emptyList()
            }
        }"""

new_extreme = """        return supervisorScope {
            val channel = kotlinx.coroutines.channels.Channel<List<InetAddress>>(hardcodedIps.size)
            val completed = java.util.concurrent.atomic.AtomicInteger(0)
            val jobs = hardcodedIps.map { url ->
                launch(ProxyDispatcher.io) {
                    try {
                        val res = queryDoh(host, url, vpnService)
                        if (res.isNotEmpty()) channel.trySend(res)
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Throwable) {
                    } finally {
                        if (completed.incrementAndGet() == hardcodedIps.size) {
                            channel.close()
                        }
                    }
                }
            }
            val result = try {
                withTimeoutOrNull(5000) { channel.receive() } ?: emptyList()
            } catch (e: Throwable) {
                emptyList()
            }
            jobs.forEach { it.cancel() }
            result
        }"""

if old_extreme in text:
    text = text.replace(old_extreme, new_extreme)
    with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DnsProtocols.kt', 'w') as f:
        f.write(text)
    print("Fixed DnsProtocols queryDohExtreme leak")
else:
    print("Not found")
