package com.aistudio.pinkproxy.fresh

import android.content.Context
import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Proactive Background Auto-Probe & Tuning Engine.
 * Quietly tests bypass candidates for key censored platforms (YouTube, Discord, Telegram, Instagram)
 * as soon as a new network connects, finding the optimal strategy BEFORE the user opens the apps.
 */
object ProactiveAutoTuner {
    private val scope = CoroutineScope(ProxyDispatcher.io + SupervisorJob() + ProxyDispatcher.globalHandler)
    private val isTuningRunning = AtomicBoolean(false)
    private var tuningJob: Job? = null

    // Target probe hosts covering distinct TSPU inspection policies
    private val PROBE_TARGETS = listOf(
        "rr1---sn-axq7sn76.googlevideo.com" to 443, // YouTube CDN stream
        "discord.com" to 443,                      // Discord Gateway / Voice
        "api.telegram.org" to 443,                 // Telegram API / CDN
        "instagram.com" to 443                     // Meta / Instagram Edge
    )

    fun startProactiveTune(context: Context, vpnService: VpnService?) {
        if (!isTuningRunning.compareAndSet(false, true)) {
            Log.v("ProactiveAutoTuner", "Auto-tune already in progress, skipping duplicate trigger.")
            return
        }

        tuningJob?.cancel()
        tuningJob = scope.launch {
            try {
                Log.i("ProactiveAutoTuner", "Starting proactive background bypass tuning for network profile: ${NetworkProfileManager.currentProfile.value.displayName}")
                
                // Small delay to let network stabilize
                delay(2000)

                for ((host, port) in PROBE_TARGETS) {
                    if (!isActive) break
                    tuneHost(host, port, vpnService)
                    delay(350) // Non-aggressive spacing to prevent radio wake overload
                }
                
                Log.i("ProactiveAutoTuner", "Proactive tuning finished successfully. Learned optimal profiles.")
            } catch (e: CancellationException) {
                // Cooperative cancel
            } catch (e: Exception) {
                Log.e("ProactiveAutoTuner", "Error during proactive auto-tuning: ${e.message}")
            } finally {
                isTuningRunning.set(false)
            }
        }
    }

    private suspend fun tuneHost(host: String, port: Int, vpnService: VpnService?) {
        val category = HostClassifier.classify(host)
        val currentBest = DpiEngine.selectStrategy(host, category, TransportType.TCP)

        // Generate synthetic realistic TLS ClientHello for the target host
        val dummyClientHello = FakePacketHelper.buildRealisticTlsHello(host)
        val ips = try {
            RobustResolver.resolve(host)
        } catch (e: Exception) {
            emptyList()
        }

        if (ips.isEmpty()) return

        // Auto-Tuner 2.0: Rank and select top candidate strategies (Current best + Thompson dynamic top + robust diverse fallback)
        val diverseExtreme = DpiStrategySelector.getDiverseFallback(failed = currentBest, category = category, transport = TransportType.TCP)
        val candidates = listOf(
            currentBest,
            BypassStrategy.SNI_SPLIT,
            BypassStrategy.TLS_SNI_EXT_MANGLE,
            BypassStrategy.BYEBYEDPI_HYBRID,
            BypassStrategy.TCP_COMBINED_HYBRID,
            diverseExtreme
        ).filter { 
            DpiStrategySelector.isFamilyCompatible(it.family, TransportType.TCP) &&
            StrategyExecutionRegistry.isExecutorSupported(it, TransportType.TCP) &&
            !DpiEngine.isBlacklisted(it, host)
        }.distinct().take(4)

        for (candidate in candidates) {
            val success = testCandidate(ips, port, host, candidate, dummyClientHello, vpnService)
            if (success) {
                Log.i("ProactiveAutoTuner", "Discovered optimal strategy $candidate for $host proactively!")
                break
            }
        }
    }

    private suspend fun testCandidate(
        ips: List<InetAddress>,
        port: Int,
        host: String,
        strategy: BypassStrategy,
        payload: ByteArray,
        vpnService: VpnService?
    ): Boolean = withContext(ProxyDispatcher.io) {
        val rtt = BypassConfig.currentRttMs.value
        val config = BypassConfig.getSessionConfig(host, strategy, rtt, TransportType.TCP)
        val socket = Socket()
        try {
            vpnService?.protect(socket)
            socket.tcpNoDelay = true
            socket.soTimeout = 1200

            val targetIp = ips.firstOrNull() ?: return@withContext false
            socket.connect(InetSocketAddress(targetIp, port), 1200)

            val out = socket.getOutputStream()
            val inStream = socket.getInputStream()
            val startTime = System.currentTimeMillis()

            BypassApplier.applyBypass(socket, out, payload, payload.size, config, host)

            val buf = ByteArray(1024)
            val read = inStream.read(buf)

            if (read > 0) {
                val latency = System.currentTimeMillis() - startTime
                // Check if response is valid TLS ServerHello (0x16, 0x03)
                val isTlsServerHello = read >= 5 && buf[0] == 0x16.toByte() && buf[1] == 0x03.toByte()
                if (isTlsServerHello) {
                    DpiEngine.recordStrategyResult(
                        host = host,
                        strat = strategy,
                        success = true,
                        latencyMs = latency,
                        quality = ObservationQuality.APPLICATION_DATA_EXCHANGED,
                        requestedStrategy = strategy,
                        effectiveStrategy = strategy,
                        transport = TransportType.TCP
                    )
                    return@withContext true
                }
            }
            DpiEngine.recordStrategyResult(
                host = host,
                strat = strategy,
                success = false,
                latencyMs = 0,
                reason = FailureReason.CENSORSHIP_STALL,
                quality = ObservationQuality.CONNECT_ONLY,
                requestedStrategy = strategy,
                effectiveStrategy = strategy,
                transport = TransportType.TCP
            )
            false
        } catch (e: Exception) {
            val reason = if (e.message?.contains("reset", ignoreCase = true) == true || e.message?.contains("broken pipe", ignoreCase = true) == true) {
                FailureReason.TCP_RESET
            } else {
                FailureReason.TIMEOUT
            }
            DpiEngine.recordStrategyResult(
                host = host,
                strat = strategy,
                success = false,
                latencyMs = 0,
                reason = reason,
                quality = ObservationQuality.CONNECT_ONLY,
                requestedStrategy = strategy,
                effectiveStrategy = strategy,
                transport = TransportType.TCP
            )
            false
        } finally {
            try { socket.close() } catch (e: Exception) {}
        }
    }
}
