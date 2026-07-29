with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt", "r") as f:
    code = f.read()

print("target_race:", """                        val channel = kotlinx.coroutines.channels.Channel<Socket>(resolved.size)
                        val activeJobs = mutableListOf<Job>()
                        // Aggressive racing: attempt more IPs if censorship is high or it is a retry""" in code)

print("target_finally:", """                        val winner = try {
                            channel.receive()
                        } catch (e: Throwable) {
                            throw Exception("All TCP connection attempts failed for $targetHost")
                        } finally {""" in code)

print("target_dpi:", """                                    if (n >= 5) {
                                        val contentType = buffer[0].toInt() and 0xFF""" in code)

print("target_sni:", """                    val clientToRemote = launch(ProxyDispatcher.io) {
                        val buffer = ProxyStats.obtain64k()""" in code)

print("target_sni_extract:", """                                        if (realSni != null) {""" in code)

print("target_apply_bypass:", """                                    // Apply full bypass to initial handshake/header packets
                                    try {
                                        BypassConfig.applyBypass(remoteSocket!!, remoteOut, buffer, n, config, targetHost)""" in code)

