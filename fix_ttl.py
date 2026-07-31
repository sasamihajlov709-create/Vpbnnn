with open('app/src/main/java/com/aistudio/pinkproxy/fresh/AutoTtlProber.kt', 'r') as f:
    text = f.read()

import re

old_est = """    private suspend fun estimateDistance(addr: InetAddress, port: Int, vpnService: VpnService?): Int {
        // Simple TCP Traceroute-like probe
        for (ttl in listOf(4, 8, 12, 16, 20, 24, 28, 32)) {
            if (tryConnect(addr, port, ttl, vpnService)) {
                // Found upper bound, now refine
                for (fineTtl in (ttl - 3)..ttl) {
                    if (tryConnect(addr, port, fineTtl, vpnService)) return fineTtl
                }
                return ttl
            }
        }
        return -1
    }"""

new_est = """    private suspend fun estimateDistance(addr: InetAddress, port: Int, vpnService: VpnService?): Int {
        return kotlinx.coroutines.withContext(ProxyDispatcher.io) {
            val ttls = listOf(4, 8, 12, 16, 20, 24, 28, 32)
            val deferreds = ttls.associateWith { ttl -> 
                kotlinx.coroutines.async { tryConnect(addr, port, ttl, vpnService) }
            }
            
            var upperBound = -1
            for (ttl in ttls) {
                if (deferreds[ttl]?.await() == true) {
                    upperBound = ttl
                    break
                }
            }
            
            if (upperBound != -1) {
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

text = text.replace(old_est, new_est)

old_tryMtu = """    private suspend fun tryMtu(addr: InetAddress, port: Int, mtu: Int, vpnService: VpnService?): Boolean {
        return withContext(ProxyDispatcher.io) {
            var socket: Socket? = null
            try {
                socket = Socket()
                vpnService?.protect(socket)
                socket.tcpNoDelay = true
                // We simulate MTU by setting MSS which is MTU - 40 (TCP+IP headers)
                TtlHelper.setMss(socket, (mtu - 40).coerceAtLeast(512))
                socket.connect(InetSocketAddress(addr, port), 2000)
                
                val output = socket.getOutputStream()
                val payload = ByteArray(mtu - 40) { 0 } // Full size segment
                output.write(payload)
                output.flush()
                
                // If it doesn't time out, the MTU is likely okay
                socket.soTimeout = 1500
                socket.getInputStream().read()
                true
            } catch (e: Throwable) {
                false
            } finally {
                try { socket?.close() } catch (e: Throwable) {}
            }
        }
    }"""

new_tryMtu = """    private suspend fun tryMtu(addr: InetAddress, port: Int, mtu: Int, vpnService: VpnService?): Boolean {
        return withContext(ProxyDispatcher.io) {
            var socket: Socket? = null
            try {
                socket = Socket()
                vpnService?.protect(socket)
                socket.tcpNoDelay = true
                TtlHelper.setMss(socket, (mtu - 40).coerceAtLeast(512))
                socket.connect(InetSocketAddress(addr, port), 1500)
                
                val output = socket.getOutputStream()
                val payload = ByteArray(mtu - 40) { 0 }
                output.write(payload)
                output.flush()
                
                socket.soTimeout = 1000
                socket.getInputStream().read()
                true
            } catch (e: Throwable) {
                false
            } finally {
                try { socket?.close() } catch (e: Throwable) {}
            }
        }
    }"""

text = text.replace(old_tryMtu, new_tryMtu)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/AutoTtlProber.kt', 'w') as f:
    f.write(text)
print("done")
