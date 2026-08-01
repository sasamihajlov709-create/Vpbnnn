import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'r') as f:
    code = f.read()

old_func = """    fun performInitialScan(context: android.content.Context) {
        scope.launch {
            Log.i("DpiEngine", "Starting automated censorship fingerprinting...")
            val targets = listOf("google.com", "youtube.com", "telegram.org")
            val probes = listOf(
                BypassStrategy.TCP_RETRANS_FAKE,
                BypassStrategy.TLS_SNI_FRAGMENT,
                BypassStrategy.SNI_SPLIT,
                BypassStrategy.TCP_SEGMENT_OVERLAP,
                BypassStrategy.ECH_GREASE,
                BypassStrategy.TCP_COMBINED_NUCLEAR
            )
            
            targets.forEach { host ->
                probes.forEach { strat ->
                    try {
                        val ok = withTimeoutOrNull(5000) {
                            RobustResolver.resolve(host)
                        }
                        if (ok != null && ok.isNotEmpty()) {
                            recordResult(strat, true, HostClassifier.classify(host), latencyMs = 100)
                        } else {
                            recordResult(strat, false, HostClassifier.classify(host), reason = FailureReason.TIMEOUT)
                        }
                    } catch (e: Throwable) {}
                    delay(500)
                }
            }
            
            context.getSharedPreferences("dpi_engine_state", android.content.Context.MODE_PRIVATE)
                .edit().putLong("last_scan_time", System.currentTimeMillis()).apply()
            Log.i("DpiEngine", "Initial scan complete. Intensity: ${ProxyStats.censorshipIntensity.value}")
        }
    }"""

new_func = """    fun performInitialScan(context: android.content.Context) {
        scope.launch {
            Log.i("DpiEngine", "Starting automated censorship fingerprinting...")
            val targets = listOf("google.com", "youtube.com", "telegram.org")
            val probes = listOf(
                BypassStrategy.TCP_RETRANS_FAKE,
                BypassStrategy.TLS_SNI_FRAGMENT,
                BypassStrategy.SNI_SPLIT,
                BypassStrategy.TCP_SEGMENT_OVERLAP,
                BypassStrategy.ECH_GREASE,
                BypassStrategy.TCP_COMBINED_NUCLEAR
            )
            
            targets.forEach { host ->
                val resolved = try { RobustResolver.resolve(host) } catch (e: Throwable) { emptyList() }
                if (resolved.isNotEmpty()) {
                    val addr = resolved.first()
                    probes.forEach { strat ->
                        try {
                            val start = System.currentTimeMillis()
                            val ok = withTimeoutOrNull(3000) {
                                val s = java.net.Socket()
                                try {
                                    s.connect(java.net.InetSocketAddress(addr, 443), 1500)
                                    val out = s.getOutputStream()
                                    // Make a fake packet using the strategy
                                    val fake = FakePacketHelper.buildRealisticTlsHello(host)
                                    val config = BypassConfig.getSessionConfig(host, strat, 50)
                                    BypassConfig.applyBypass(s, out, fake, fake.size, config, host)
                                    // Wait for some data to see if we survived DPI
                                    s.soTimeout = 1500
                                    val i = s.getInputStream().read()
                                    i != -1
                                } catch (e: Throwable) {
                                    false
                                } finally {
                                    try { s.close() } catch (e: Throwable) {}
                                }
                            }
                            val latency = System.currentTimeMillis() - start
                            if (ok == true) {
                                recordResult(strat, true, HostClassifier.classify(host), latencyMs = latency)
                            } else {
                                recordResult(strat, false, HostClassifier.classify(host), reason = FailureReason.CONNECTION_REFUSED)
                            }
                        } catch (e: Throwable) {}
                        delay(200)
                    }
                }
            }
            
            context.getSharedPreferences("dpi_engine_state", android.content.Context.MODE_PRIVATE)
                .edit().putLong("last_scan_time", System.currentTimeMillis()).apply()
            Log.i("DpiEngine", "Initial scan complete. Intensity: ${ProxyStats.censorshipIntensity.value}")
        }
    }"""

if old_func in code:
    with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'w') as f:
        f.write(code.replace(old_func, new_func))
else:
    print("Could not find the block to replace")

