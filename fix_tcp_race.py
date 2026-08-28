with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpRaceConnector.kt", "r") as f:
    text = f.read()

import re

# Fix runSingleAttempt sending
old_send1 = r'''if \(res != null\) resultChannel\.send\(res\)'''
new_send1 = '''if (res != null) {
                    if (!resultChannel.trySend(res).isSuccess) {
                        try { res.socket.close() } catch (e: Exception) {}
                    }
                }'''
text = re.sub(old_send1, new_send1, text)

# Fix finally block
old_finally = r'''        finally \{
            job1\.cancel\(\)
            job2\.cancel\(\)
            
            // Close any losers
            launch\(ProxyDispatcher\.io\) \{
                repeat\(2\) \{
                    val other = resultChannel\.tryReceive\(\)\.getOrNull\(\)
                    if \(other != null && other\.socket != winner\?\.socket\) \{
                        try \{ 
                            other\.input\.close\(\)
                            other\.output\.close\(\)
                            try \{ other\.socket\.setSoLinger\(true, 0\) \} catch \(ignored: Exception\) \{\}
                            other\.socket\.close\(\) 
                        \} catch \(e: Throwable\) \{
                            Log\.v\("TcpRaceConnector", "Failed to close loser socket: \$\{e\.message\}"\)
                        \}
                    \}
                \}
                resultChannel\.close\(\)
            \}
        \}'''
new_finally = '''        finally {
            job1.cancel()
            job2.cancel()
            resultChannel.close()
            
            // Close any losers
            while (true) {
                val other = resultChannel.tryReceive().getOrNull() ?: break
                if (other.socket != winner?.socket) {
                    try { 
                        other.input.close()
                        other.output.close()
                        try { other.socket.setSoLinger(true, 0) } catch (ignored: Exception) {}
                        other.socket.close() 
                    } catch (e: Throwable) {
                        Log.v("TcpRaceConnector", "Failed to close loser socket: ${e.message}")
                    }
                }
            }
        }'''
text = re.sub(old_finally, new_finally, text)

# Let's fix catch CancellationException swallowing in runSingleAttempt
old_catch = r'''        \} catch \(e: Throwable\) \{
            val reason = if \(e\.message\?\.contains\("reset", ignoreCase = true\) == true \|\| e\.message\?\.contains\("broken pipe", ignoreCase = true\) == true\) \{
                FailureReason\.TCP_RESET
            \} else \{
                FailureReason\.TIMEOUT
            \}
            DpiStrategySelector\.recordResult\(
                host = host,
                strategy = strategy,
                success = false,
                transport = TransportType\.TCP,
                quality = ObservationQuality\.CONNECT_ONLY,
                latencyMs = 0,
                reason = reason,
                requestedStrategy = requestedStrategy,
                effectiveStrategy = effectiveStrategy
            \)
            try \{ rs\.close\(\) \} catch \(ex: Throwable\) \{\}
            return null
        \}'''
new_catch = '''        } catch (e: Throwable) {
            val reason = if (e.message?.contains("reset", ignoreCase = true) == true || e.message?.contains("broken pipe", ignoreCase = true) == true) {
                FailureReason.TCP_RESET
            } else {
                FailureReason.TIMEOUT
            }
            DpiStrategySelector.recordResult(
                host = host,
                strategy = strategy,
                success = false,
                transport = TransportType.TCP,
                quality = ObservationQuality.CONNECT_ONLY,
                latencyMs = 0,
                reason = reason,
                requestedStrategy = requestedStrategy,
                effectiveStrategy = effectiveStrategy
            )
            try { rs.close() } catch (ex: Throwable) {}
            if (e is CancellationException) throw e
            return null
        }'''
text = re.sub(old_catch, new_catch, text)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpRaceConnector.kt", "w") as f:
    f.write(text)
