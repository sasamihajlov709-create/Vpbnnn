with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt", "r") as f:
    code = f.read()

target_race = """                        val channel = kotlinx.coroutines.channels.Channel<Socket>(resolved.size)
                        val activeJobs = mutableListOf<Job>()
                        // Aggressive racing: attempt more IPs if censorship is high or it is a retry"""

replacement_race = """                        val channel = kotlinx.coroutines.channels.Channel<Socket>(resolved.size)
                        val activeJobs = mutableListOf<Job>()
                        val attemptedSockets = java.util.concurrent.CopyOnWriteArrayList<Socket>()
                        // Aggressive racing: attempt more IPs if censorship is high or it is a retry"""

target_job_launch = """                            activeJobs += scope.launch(ProxyDispatcher.io) {
                                val s = Socket()"""

replacement_job_launch = """                            activeJobs += scope.launch(ProxyDispatcher.io) {
                                val s = Socket()
                                attemptedSockets.add(s)"""

target_finally = """                        val winner = try {
                            channel.receive()
                        } catch (e: Throwable) {
                            throw Exception("All TCP connection attempts failed for $targetHost")
                        } finally {
                            channel.close()
                            activeJobs.forEach { it.cancel() }
                            while (true) {
                                val leftover = channel.tryReceive().getOrNull() ?: break
                                try { leftover.close() } catch (e: Throwable) {}
                            }
                        }"""

replacement_finally = """                        val winner = try {
                            channel.receive()
                        } catch (e: Throwable) {
                            throw Exception("All TCP connection attempts failed for $targetHost")
                        } finally {
                            channel.close()
                            activeJobs.forEach { it.cancel() }
                            attemptedSockets.forEach { s ->
                                if (s != winner) {
                                    try { s.close() } catch (e: Throwable) {}
                                }
                            }
                            while (true) {
                                val leftover = channel.tryReceive().getOrNull() ?: break
                                try { leftover.close() } catch (e: Throwable) {}
                            }
                        }"""

target_dpi = """                                    if (n >= 5) {
                                        val contentType = buffer[0].toInt() and 0xFF
                                        if (contentType == 0x15) { // TLS Alert"""

replacement_dpi = """                                    if (n >= 7) {
                                        val contentType = buffer[0].toInt() and 0xFF
                                        if (contentType == 0x15) { // TLS Alert"""

target_sni = """                val clientToRemote = launch(ProxyDispatcher.io) {
                    val buffer = ProxyStats.obtain64k()
                    val rnd = ThreadLocalRandom.current()"""

replacement_sni = """                val clientToRemote = launch(ProxyDispatcher.io) {
                    val buffer = ProxyStats.obtain64k()
                    val rnd = ThreadLocalRandom.current()
                    var detectedSni: String? = null"""

target_apply_bypass = """                                    // Apply full bypass to initial handshake/header packets
                                    try {
                                        BypassConfig.applyBypass(remoteSocket!!, remoteOut, buffer, n, config, targetHost)
                                    } catch (e: Throwable) {
                                        if (e is CancellationException) throw e
                                        BypassConfig.recordFailure(strategy, targetHost)
                                        throw e
                                    }"""

replacement_apply_bypass = """                                    // Apply full bypass to initial handshake/header packets
                                    val activeHost = detectedSni ?: targetHost
                                    try {
                                        BypassConfig.applyBypass(remoteSocket!!, remoteOut, buffer, n, config, activeHost)
                                    } catch (e: Throwable) {
                                        if (e is CancellationException) throw e
                                        BypassConfig.recordFailure(strategy, activeHost)
                                        throw e
                                    }"""

if target_race in code and target_job_launch in code and target_finally in code and target_dpi in code and target_sni in code:
    code = code.replace(target_race, replacement_race, 1)
    code = code.replace(target_job_launch, replacement_job_launch, 1)
    code = code.replace(target_finally, replacement_finally, 1)
    code = code.replace(target_dpi, replacement_dpi, 1)
    code = code.replace(target_sni, replacement_sni, 1)
    code = code.replace(target_apply_bypass, replacement_apply_bypass, 1)
    with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt", "w") as f:
        f.write(code)
    print("TcpTransportHandler updated successfully")
else:
    print("Target match failed!")

