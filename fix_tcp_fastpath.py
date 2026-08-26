import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt", "r") as f:
    content = f.read()

loop_pattern = """                    var packetIndex = 0
                    while (isActive) {
                        val read = clientIn.read(clientBuffer)"""

new_loop_pattern = """                    var packetIndex = 0
                    var fastPathActive = false
                    while (isActive) {
                        val read = clientIn.read(clientBuffer)"""

content = content.replace(loop_pattern, new_loop_pattern)

body_pattern = """                        // Inspect secondary payloads on Keep-Alive / Multiplexed streams
                        val isSecondaryTlsOrHttp = packetIndex > 1 && (BypassApplier.isProbableTls(clientBuffer, read) || BypassApplier.isProbableHttp(clientBuffer, read))
                        
                        writeMutex.lock()
                        try {
                            if (isSecondaryTlsOrHttp && effectiveStrategy != BypassStrategy.DIRECT) {
                                Log.v("TcpTransport", "Detected secondary TLS/HTTP payload in packet #$packetIndex for $targetHost - applying evasion")
                                BypassApplier.applyBypass(finalRemoteSocket, finalRemoteOut, clientBuffer, read, config, targetHost)
                            } else {
                                finalRemoteOut.write(clientBuffer, 0, read)
                                finalRemoteOut.flush()
                            }
                        } finally {
                            writeMutex.unlock()
                        }
                        totalWrittenClient.addAndGet(read.toLong())
                        ProxyStats.recordStats(sessionId, read.toLong(), 0)
                    }"""

new_body_pattern = """                        if (fastPathActive) {
                            writeMutex.lock()
                            try {
                                finalRemoteOut.write(clientBuffer, 0, read)
                                finalRemoteOut.flush()
                            } finally {
                                writeMutex.unlock()
                            }
                        } else {
                            if (read >= 5 && clientBuffer[0] == 0x17.toByte() && targetPort == 443) {
                                fastPathActive = true
                            }
                            // Inspect secondary payloads on Keep-Alive / Multiplexed streams
                            val isSecondaryTlsOrHttp = packetIndex > 1 && (BypassApplier.isProbableTls(clientBuffer, read) || BypassApplier.isProbableHttp(clientBuffer, read))
                            
                            writeMutex.lock()
                            try {
                                if (isSecondaryTlsOrHttp && effectiveStrategy != BypassStrategy.DIRECT) {
                                    Log.v("TcpTransport", "Detected secondary TLS/HTTP payload in packet #$packetIndex for $targetHost - applying evasion")
                                    BypassApplier.applyBypass(finalRemoteSocket, finalRemoteOut, clientBuffer, read, config, targetHost)
                                } else {
                                    finalRemoteOut.write(clientBuffer, 0, read)
                                    finalRemoteOut.flush()
                                }
                            } finally {
                                writeMutex.unlock()
                            }
                        }
                        totalWrittenClient.addAndGet(read.toLong())
                        ProxyStats.recordStats(sessionId, read.toLong(), 0)
                    }"""

content = content.replace(body_pattern, new_body_pattern)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt", "w") as f:
    f.write(content)
