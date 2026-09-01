import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt", "r") as f:
    content = f.read()

old_catch = """            } catch (e: Exception) {
                if (e is CancellationException) {
                    try { rs.close() } catch (ex: Exception) {}
                    throw e
                }
                val reason = if (e.message?.contains("reset", ignoreCase = true) == true || e.message?.contains("broken pipe", ignoreCase = true) == true) {
                    FailureReason.TCP_RESET
                } else {
                    FailureReason.TIMEOUT
                }
                DpiStrategySelector.recordResult(
                    host = targetHost,
                    strategy = currentStrategy,
                    success = false,
                    transport = TransportType.TCP,
                    quality = ObservationQuality.CONNECT_ONLY,
                    latencyMs = 0,
                    reason = reason,
                    requestedStrategy = requestedStrategy,
                    effectiveStrategy = primaryStrategy
                )
                Log.w("TcpTransport", "Connection error on strategy $currentStrategy for $targetHost: ${e.message}. Rescuing with fallback.")
                try { rs.close() } catch (ex: Exception) {}

                val nextStrat = StrategyEscalationGraph.getEscalatedStrategy(
                    failedStrategy = currentStrategy,
                    reason = reason,
                    transport = TransportType.TCP,
                    host = targetHost,
                    category = category
                ) ?: DpiStrategySelector.getFallbackStrategy(currentStrategy, TransportType.TCP)
                currentStrategy = if (nextStrat !in attemptedStrategies) nextStrat else DpiStrategySelector.getFallbackStrategy(currentStrategy, TransportType.TCP)
            }"""

new_catch = """            } catch (e: Exception) {
                if (e is CancellationException) {
                    try { rs.close() } catch (ex: Exception) {}
                    throw e
                }
                
                if (e is DnsException || e is java.net.UnknownHostException) {
                    android.util.Log.w("TcpTransport", "DNS error for $targetHost, skipping strategy penalty.")
                    try { rs.close() } catch (ex: Exception) {}
                    return null 
                }
                
                val reason = when {
                    e is StrategyException -> e.reason
                    e is TransportException -> FailureReason.TARGET_UNAVAILABLE
                    e.message?.contains("reset", ignoreCase = true) == true || e.message?.contains("broken pipe", ignoreCase = true) == true -> FailureReason.TCP_RESET
                    e is java.net.ConnectException -> FailureReason.CONNECTION_REFUSED
                    else -> FailureReason.TIMEOUT
                }
                
                // Пенализируем только если это не TransportException
                if (e !is TransportException) {
                    DpiStrategySelector.recordResult(
                        host = targetHost,
                        strategy = currentStrategy,
                        success = false,
                        transport = TransportType.TCP,
                        quality = ObservationQuality.CONNECT_ONLY,
                        latencyMs = 0,
                        reason = reason,
                        requestedStrategy = requestedStrategy,
                        effectiveStrategy = primaryStrategy
                    )
                } else {
                    android.util.Log.d("TcpTransport", "TransportException: not penalizing strategy $currentStrategy")
                }
                
                android.util.Log.w("TcpTransport", "Connection error on strategy $currentStrategy for $targetHost: ${e.message}. Rescuing with fallback.")
                try { rs.close() } catch (ex: Exception) {}

                val nextStrat = StrategyEscalationGraph.getEscalatedStrategy(
                    failedStrategy = currentStrategy,
                    reason = reason,
                    transport = TransportType.TCP,
                    host = targetHost,
                    category = category
                ) ?: DpiStrategySelector.getFallbackStrategy(currentStrategy, TransportType.TCP)
                currentStrategy = if (nextStrat !in attemptedStrategies) nextStrat else DpiStrategySelector.getFallbackStrategy(currentStrategy, TransportType.TCP)
            }"""

content = content.replace(old_catch, new_catch)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt", "w") as f:
    f.write(content)

