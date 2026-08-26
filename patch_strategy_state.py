with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "r") as f:
    content = f.read()

old_penalty = """        } else {
            failureCount.incrementAndGet()
            val penalty = when (obs.failureReason) {
                FailureReason.TCP_RESET, FailureReason.SSL_HANDSHAKE_ERROR, FailureReason.CENSORSHIP_STALL, FailureReason.DNS_POISONED, FailureReason.PROTOCOL_ERROR -> 1000L // 1.0 weight
                FailureReason.TIMEOUT, FailureReason.HANDSHAKE_TIMEOUT -> 500L // 0.5 weight
                FailureReason.CONNECTION_REFUSED, FailureReason.MTU_EXCEEDED -> 200L // 0.2 weight
                FailureReason.UNKNOWN, null -> 800L
            }
            weightedFailure.addAndGet(penalty)
        }"""

new_penalty = """        } else {
            failureCount.incrementAndGet()
            val penalty = when (obs.failureReason) {
                // Strategy Failures (High Penalty)
                FailureReason.TCP_RESET, FailureReason.SSL_HANDSHAKE_ERROR, FailureReason.CENSORSHIP_STALL, FailureReason.DNS_POISONED, FailureReason.PROTOCOL_ERROR -> 1000L // 1.0 weight
                FailureReason.TIMEOUT, FailureReason.HANDSHAKE_TIMEOUT -> 500L // 0.5 weight
                
                // Target Failures (Low Penalty, might just be offline server)
                FailureReason.CONNECTION_REFUSED, FailureReason.MTU_EXCEEDED, FailureReason.TARGET_UNAVAILABLE -> 100L // 0.1 weight
                
                // Network / Local Failures (Ignore or tiny penalty to preserve strategy rating)
                FailureReason.NETWORK_LOST, FailureReason.LOCAL_SOCKET_ERROR -> 0L // 0 weight
                
                FailureReason.UNKNOWN, null -> 200L // Reduced from 800L
            }
            weightedFailure.addAndGet(penalty)
        }"""

content = content.replace(old_penalty, new_penalty)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "w") as f:
    f.write(content)
