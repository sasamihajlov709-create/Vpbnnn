package com.aistudio.pinkproxy.fresh

import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.ConcurrentHashMap

object BenchmarkManager {
    data class BenchmarkResult(
        val strategy: BypassStrategy,
        val isTested: Boolean = false,
        val isSuccess: Boolean = false,
        val latencyMs: Long = 0,
        val error: String? = null
    )

    private val _isRunning = MutableStateFlow(false)
    val isRunning = _isRunning.asStateFlow()

    private val _progress = MutableStateFlow(0f)
    val progress = _progress.asStateFlow()

    private val _results = MutableStateFlow<List<BenchmarkResult>>(emptyList())
    val results = _results.asStateFlow()

    private var benchmarkJob: Job? = null

    fun startBenchmark(scope: CoroutineScope, proxyPort: Int) {
        if (_isRunning.value) return
        _isRunning.value = true
        _progress.value = 0f
        
        BypassConfig.isBenchmarkModeEnabled = true
        
        val strategies = BypassStrategy.entries.filter { 
            it != BypassStrategy.DIRECT && 
            StrategyExecutionRegistry.isExecutorSupported(it, TransportType.TCP) 
        }
        _results.value = strategies.map { BenchmarkResult(it) }

        benchmarkJob = scope.launch(Dispatchers.IO) {
            try {
                val testHosts = listOf(
                    "YouTube" to "https://www.youtube.com",
                    "Google" to "https://www.google.com",
                    "GitHub" to "https://github.com"
                )

                strategies.forEachIndexed { index, strategy ->
                    if (!isActive) return@forEachIndexed
                    
                    val attemptResults = mutableListOf<Pair<Pair<String, String>, ServiceChecker.ServiceStatus>>()
                    for (testHost in testHosts) {
                        if (!isActive) break
                        val status = NetworkProber.probeServiceViaProxy(testHost.first, testHost.second, proxyPort, strategy.name)
                        attemptResults.add(testHost to status)
                    }

                    val successCount = attemptResults.count { it.second.isUp }
                    val avgLatency = if (successCount > 0) {
                        attemptResults.filter { it.second.isUp }.map { it.second.latencyMs }.average().toLong()
                    } else 0L

                    // Feed confirmed benchmark results individually per host
                    attemptResults.forEach { (hostInfo, result) ->
                        val (name, url) = hostInfo
                        val host = try { java.net.URL(url).host } catch (e: Exception) { name.lowercase() }
                        DpiStrategySelector.recordResult(
                            host = host,
                            strategy = strategy,
                            success = result.isUp,
                            transport = TransportType.TCP,
                            quality = if (result.isUp) ObservationQuality.APPLICATION_DATA_EXCHANGED else ObservationQuality.CONNECT_ONLY,
                            requestedStrategy = strategy,
                            effectiveStrategy = strategy,
                            latencyMs = result.latencyMs
                        )
                    }

                    val newResult = BenchmarkResult(
                        strategy = strategy,
                        isTested = true,
                        isSuccess = successCount > 0,
                        latencyMs = avgLatency,
                        error = if (successCount == 0) "All probes failed" else null
                    )

                    val currentResults = _results.value.toMutableList()
                    val idx = currentResults.indexOfFirst { it.strategy == strategy }
                    if (idx != -1) {
                        currentResults[idx] = newResult
                        _results.value = currentResults
                    }

                    _progress.value = (index + 1).toFloat() / strategies.size
                    
                    // Small delay between strategies to avoid overwhelming local stack
                    delay(500)
                }
            } catch (e: Exception) {
                Log.e("BenchmarkManager", "Benchmark failed", e)
            } finally {
                BypassConfig.isBenchmarkModeEnabled = false
                _isRunning.value = false
                _progress.value = 1f
            }
        }
    }

    fun stopBenchmark() {
        benchmarkJob?.cancel()
        BypassConfig.isBenchmarkModeEnabled = false
        _isRunning.value = false
    }
}
