import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt', 'r') as f:
    tuner = f.read()

# Fix return in startProactiveTune
tuner = re.sub(r'Log\.v\("ProactiveAutoTuner", "Auto-tune already in progress, skipping duplicate trigger\."\)\s*return false', r'Log.v("ProactiveAutoTuner", "Auto-tune already in progress, skipping duplicate trigger.")\n            return', tuner)

# Fix return in tuneHost
tuner = re.sub(r'if \(ips\.isEmpty\(\)\) return false', r'if (ips.isEmpty()) return', tuner)

# Fix the end of the file which is cut off
good_end = """        try {
            val socket = HappyEyeballsConnector.connectHappyEyeballs(ips, port, vpnService, host)
            if (socket != null) {
                try {
                    val out = socket.getOutputStream()
                    val inStream = socket.getInputStream()
                    val startTime = System.currentTimeMillis()
                    
                    BypassApplier.applyBypass(socket, out, payload, payload.size, config, host)
                    
                    val buf = ByteArray(2048)
                    val read = inStream.read(buf)
                    
                    if (read > 0) {
                        val latency = System.currentTimeMillis() - startTime
                        val isTlsServerHello = read >= 5 && buf[0] == 0x16.toByte() && buf[1] == 0x03.toByte()
                        if (isTlsServerHello) {
                            DpiStrategySelector.recordResult(
                                strategy = strategy,
                                success = true,
                                transport = TransportType.TCP,
                                category = HostClassifier.classify(host),
                                host = host,
                                latencyMs = latency,
                                quality = ObservationQuality.TLS_RECORD_RECEIVED
                            )
                            return@withContext true
                        }
                    }
                } finally {
                    try { socket.close() } catch (e: Exception) {}
                }
            }
        } catch (e: Exception) {
            // ignore
        }
        
        DpiStrategySelector.recordResult(
            strategy = strategy,
            success = false,
            transport = TransportType.TCP,
            category = HostClassifier.classify(host),
            host = host,
            latencyMs = 0L,
            reason = FailureReason.TIMEOUT,
            quality = ObservationQuality.CONNECT_ONLY
        )
        return@withContext false
    }
}
"""

# Find where testCandidate `try {` starts and replace everything after it.
match = re.search(r'val config = BypassConfig\.getSessionConfig\(host, strategy, rtt, TransportType\.TCP\).*?try \{', tuner, flags=re.DOTALL)
if match:
    idx = match.end() - 4 # index of `try {`
    tuner = tuner[:idx] + good_end

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt', 'w') as f:
    f.write(tuner)

